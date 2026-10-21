/* proxy.c — backend matching, forwarding and response relay.
 *
 * When proxy mode is active (g_cfg.n_backends > 0), the request
 * pipeline checks proxy_match() before the normal static/PHP path.
 * If a backend claims the route, the request goes through the
 * sanitization pipeline (sanitize.c) and is forwarded to the
 * backend over a Unix socket — either FastCGI (for PHP-FPM) or
 * plain HTTP/1.1 (for Node).
 *
 * This is optional and off by default.  With n_backends == 0 the
 * server behaves exactly as before.
 */
#include "userver.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <ctype.h>

UProxyStats g_proxy_stats[PROXY_MAX_BACKENDS];

/* ── backend matching ────────────────────────────────────────────── */

UBackend* proxy_match(const UReq* req) {
    if (g_cfg.n_backends == 0) return NULL;

    for (int i = 0; i < g_cfg.n_backends; i++) {
        UBackend* be = &g_cfg.backends[i];
        for (int j = 0; j < be->n_routes; j++) {
            size_t rlen = strlen(be->routes[j]);
            if (!strncmp(req->path, be->routes[j], rlen)) return be;
        }
    }
    return NULL;
}

/* ── Unix socket connection ──────────────────────────────────────── */

static int connect_unix(const char* path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);

    if (connect(fd, (struct sockaddr*)&addr, sizeof addr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ── HTTP/1.1 forwarding (for Node backends) ─────────────────────── */

/* Build an HTTP/1.1 request from the sanitized UReq and send it
   over the Unix socket.  Read the response and parse it into resp. */
static int http_forward(int sock_fd, UReq* req, UResp* resp) {
    UBuf out = {0};

    /* Request line */
    ubuf_printf(&out, "%s %s HTTP/1.1\r\n", req->method, req->uri);

    /* Headers */
    for (int i = 0; i < req->nh; i++) {
        ubuf_printf(&out, "%s: %s\r\n", req->h[i].name, req->h[i].value);
    }

    /* Ensure Content-Length is present for bodies */
    if (req->body_len > 0 && !ureq_header(req, "content-length")) {
        ubuf_printf(&out, "content-length: %zu\r\n", req->body_len);
    }

    /* Connection: close — we use one connection per request */
    ubuf_adds(&out, "connection: close\r\n");
    ubuf_adds(&out, "\r\n");

    /* Send request header */
    const uint8_t* p = (const uint8_t*)out.data;
    size_t left = out.len;
    while (left > 0) {
        ssize_t w = write(sock_fd, p, left);
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; ubuf_free(&out); goto err; }
        p += w; left -= (size_t)w;
    }
    ubuf_free(&out);

    /* Send body */
    if (req->body_len > 0) {
        p = (const uint8_t*)req->body;
        left = req->body_len;
        while (left > 0) {
            ssize_t w = write(sock_fd, p, left);
            if (w <= 0) { if (w < 0 && errno == EINTR) continue; goto err; }
            p += w; left -= (size_t)w;
        }
    }

    /* Read the response */
    UBuf raw = {0};
    char buf[8192];
    for (;;) {
        ssize_t r = read(sock_fd, buf, sizeof buf);
        if (r == 0) break;
        if (r < 0) { if (errno == EINTR) continue; ubuf_free(&raw); goto err; }
        ubuf_add(&raw, buf, (size_t)r);
        /* Safety limit: 64 MiB response */
        if (raw.len > (64u << 20)) { ubuf_free(&raw); goto err; }
    }

    /* Parse HTTP response */
    uresp_init(resp);

    char* data = raw.data;
    size_t dlen = raw.len;
    if (!data || dlen < 12) { ubuf_free(&raw); goto err; }

    /* Status line: HTTP/1.1 200 OK */
    char* sep = memmem(data, dlen, "\r\n\r\n", 4);
    if (!sep) { ubuf_free(&raw); goto err; }

    /* Parse status code from first line */
    if (!strncmp(data, "HTTP/1.", 7) && data[8] == ' ') {
        resp->status = atoi(data + 9);
    } else {
        resp->status = 502;
    }

    /* Parse response headers */
    char* line = memmem(data, (size_t)(sep - data), "\r\n", 2);
    if (line) line += 2;  /* skip status line */
    while (line && line < sep) {
        char* eol = memmem(line, (size_t)(sep - line), "\r\n", 2);
        if (!eol) break;
        size_t ll = (size_t)(eol - line);

        char* colon = memchr(line, ':', ll);
        if (colon) {
            *colon = 0;
            char* v = colon + 1;
            while (*v == ' ') v++;

            /* Skip hop-by-hop headers */
            if (strcasecmp(line, "transfer-encoding") &&
                strcasecmp(line, "connection") &&
                strcasecmp(line, "keep-alive")) {
                char name[128], val[4096];
                snprintf(name, sizeof name, "%s", line);
                size_t vl = ll - (size_t)(v - line);
                snprintf(val, sizeof val, "%.*s", (int)vl, v);
                uresp_header(resp, name, val);
                if (!strcasecmp(name, "content-type")) resp->has_ctype = 1;
            }
        }
        line = eol + 2;
    }

    /* Body */
    char* body_start = sep + 4;
    size_t body_len = dlen - (size_t)(body_start - data);
    if (body_len > 0) ubuf_add(&resp->body, body_start, body_len);

    ubuf_free(&raw);
    return 1;

err:
    uresp_init(resp);
    resp->status = 502;
    resp->close = 1;
    uresp_header(resp, "Content-Type", "text/plain; charset=utf-8");
    ubuf_adds(&resp->body, "Bad Gateway: Backend connection error");
    return 1;
}

/* ── response sanitization ───────────────────────────────────────── */

static void sanitize_response(UResp* resp) {
    /* Strip Server header to avoid leaking backend versions.
       UResp.head is a flat "Name: value\r\n" buffer, so we scan and
       remove the line in place. */
    if (g_cfg.proxy_strip_server && resp->head.data) {
        char* p = resp->head.data;
        char* end = p + resp->head.len;
        while (p < end) {
            char* eol = memmem(p, (size_t)(end - p), "\r\n", 2);
            if (!eol) break;
            size_t linelen = (size_t)(eol - p) + 2;
            if ((eol - p) > 7 && !strncasecmp(p, "server:", 7)) {
                memmove(p, eol + 2, (size_t)(end - eol - 2));
                resp->head.len -= linelen;
                resp->head.data[resp->head.len] = 0;
                end = resp->head.data + resp->head.len;
                /* Don't advance p — next line is now at same position */
            } else {
                p = eol + 2;
            }
        }
    }

    /* Add security headers if configured and not already present */
    if (g_cfg.proxy_add_security_headers) {
        /* These are additive — if the backend sent them, the client
           gets both (the backend's value takes precedence in most
           browsers for the first occurrence). */
        uresp_header(resp, "X-Content-Type-Options", "nosniff");
        uresp_header(resp, "X-Frame-Options", "SAMEORIGIN");
        uresp_header(resp, "Referrer-Policy", "strict-origin-when-cross-origin");
    }
}

/* ── public entry point ──────────────────────────────────────────── */

int proxy_dispatch(UConn* c, UReq* req, UResp* resp, UBackend* be, double t0) {
    int idx = (int)(be - g_cfg.backends);

    /* Run the sanitization pipeline */
    if (sanitize_request(req, resp, &be->constraints)) {
        atomic_fetch_add(&g_proxy_stats[idx].rejected, 1);
        fprintf(stderr, "[proxy] rejected %s %s → %s (status %d)\n",
                req->method, req->uri, be->name, resp->status);
        return 1;  /* response already filled with rejection */
    }

    /* Connect to the backend */
    int sock = connect_unix(be->socket_path);
    if (sock < 0) {
        uresp_init(resp);
        resp->status = 502;
        resp->close = 1;
        uresp_header(resp, "Content-Type", "text/plain; charset=utf-8");
        ubuf_printf(&resp->body, "Bad Gateway: Cannot connect to %s backend", be->name);
        atomic_fetch_add(&g_proxy_stats[idx].errors, 1);
        fprintf(stderr, "[proxy] connect failed for %s: %s\n", be->socket_path, strerror(errno));
        return 1;
    }

    int ok;
    if (be->protocol == PROTO_FASTCGI) {
        /* Determine script filename */
        const char* docroot = be->document_root ? be->document_root : g_cfg.root;
        char script[4096];
        snprintf(script, sizeof script, "%s%s", docroot, req->path);

        /* If path ends with / or has no extension, assume index.php */
        size_t slen = strlen(script);
        if (slen > 0 && script[slen - 1] == '/') {
            snprintf(script + slen, sizeof(script) - slen, "index.php");
        } else {
            const char* dot = strrchr(req->path, '.');
            if (!dot) {
                /* No extension — route to a front controller */
                snprintf(script, sizeof script, "%sindex.php", docroot);
            }
        }

        ok = fastcgi_forward(sock, req, resp, docroot, script);
    } else {
        ok = http_forward(sock, req, resp);
    }

    close(sock);

    if (ok) {
        sanitize_response(resp);
        double elapsed = (now_s() - t0) * 1e6;
        atomic_fetch_add(&g_proxy_stats[idx].forwarded, 1);
        atomic_fetch_add(&g_proxy_stats[idx].us_total, (uint64_t)elapsed);
    }

    return 1;
}
