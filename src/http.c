/* http.c — incremental HTTP/1.1 request parsing.
 *
 * The validation rules are Qbix Server's (WebServer::parseRequest and
 * onClientData), so the two servers refuse the same requests with the same
 * status:
 *   - a request line must match  METHOD SP target SP HTTP/d.d   -> else 400
 *   - a known method in the wrong case ("get")                   -> 501
 *   - a header name that is not an RFC 9110 token                -> 400
 *   - two Host headers                                           -> 400
 *   - more than max_header bytes before the blank line           -> 431
 *   - Content-Length above max_post (8 MiB, PHP's post_max_size) -> 413
 * then: obs-fold continuation lines are joined, repeated headers are
 * combined with ", ", HTTP/1.0 without Connection means close, and a
 * chunked body is decoded. Unlike Qbix, the body is located by
 * Content-Length for every method (Qbix only looked for one when the method
 * started with 'P'), and only the bytes of this request are consumed, so a
 * pipelined request after it stays in the buffer.
 */
#include "userver.h"
#include <ctype.h>
#include <limits.h>

const char* http_reason(int s) {
    switch (s) {
    case 100: return "Continue"; case 101: return "Switching Protocols";
    case 200: return "OK"; case 201: return "Created"; case 202: return "Accepted"; case 204: return "No Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently"; case 302: return "Found"; case 303: return "See Other";
    case 304: return "Not Modified"; case 307: return "Temporary Redirect"; case 308: return "Permanent Redirect";
    case 400: return "Bad Request"; case 401: return "Unauthorized"; case 403: return "Forbidden";
    case 404: return "Not Found"; case 405: return "Method Not Allowed"; case 408: return "Request Timeout";
    case 409: return "Conflict"; case 410: return "Gone"; case 411: return "Length Required";
    case 413: return "Payload Too Large"; case 414: return "URI Too Long"; case 415: return "Unsupported Media Type";
    case 416: return "Range Not Satisfiable"; case 418: return "I'm a teapot"; case 422: return "Unprocessable Content";
    case 429: return "Too Many Requests"; case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error"; case 501: return "Not Implemented"; case 502: return "Bad Gateway";
    case 503: return "Service Unavailable"; case 504: return "Gateway Timeout";
    }
    return "OK";
}

const char* ureq_header(const UReq* r, const char* lname) {
    for (int i = 0; i < r->nh; i++) if (!strcmp(r->h[i].name, lname)) return r->h[i].value;
    return NULL;
}

static char* keep(UReq* r, char* p) {
    r->allocs = realloc(r->allocs, sizeof(char*) * (size_t)(r->nallocs + 1));
    r->allocs[r->nallocs++] = p;
    return p;
}

void ureq_free(UReq* r) {
    for (int i = 0; i < r->nallocs; i++) free(r->allocs[i]);
    free(r->allocs); free(r->mem); free(r->bodymem); free(r->path);
    memset(r, 0, sizeof *r);
}

static int is_tchar(unsigned char c) {
    return isalnum(c) || strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static void err_simple(UResp* e, int status, const char* body) {
    uresp_init(e);
    e->status = status; e->close = 1;
    uresp_header(e, "Content-Type", "text/plain; charset=utf-8");
    ubuf_adds(&e->body, body);
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode the path: %XX only ('+' stays '+'; that rule is for query
   strings), note a decoded NUL, collapse runs of '/'. */
static char* decode_path(const char* s, size_t n, int* has_nul) {
    char* out = malloc(n + 1); size_t w = 0;
    *has_nul = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '%' && i + 2 < n) {
            int a = hexval((unsigned char)s[i + 1]), b = hexval((unsigned char)s[i + 2]);
            if (a >= 0 && b >= 0) { c = (char)(a * 16 + b); i += 2; if (c == 0) { *has_nul = 1; c = ' '; } }
        }
        if (c == '/' && w > 0 && out[w - 1] == '/') continue;
        out[w++] = c;
    }
    out[w] = 0;
    return out;
}

/* chunked body starting at p (len bytes available).
   Returns bytes consumed (including the final CRLF), 0 if incomplete, -1 if malformed. */
static long dechunk(const char* p, size_t len, UBuf* out, size_t limit) {
    size_t i = 0;
    for (;;) {
        const char* nl = memmem(p + i, len - i, "\r\n", 2);
        if (!nl) return len - i > 32 ? -1 : 0;
        /* Reject leading whitespace — strtoul silently skips it,
           which could let it parse a number from the wrong line. */
        if (!isxdigit((unsigned char)p[i])) return -1;
        char* end; unsigned long sz = strtoul(p + i, &end, 16);
        if (end == p + i || sz == ULONG_MAX) return -1;
        i = (size_t)(nl - p) + 2;
        if (sz == 0) {
            /* trailers until an empty line */
            for (;;) {
                const char* tl = memmem(p + i, len - i, "\r\n", 2);
                if (!tl) return 0;
                size_t l = (size_t)(tl - (p + i));
                i += l + 2;
                if (l == 0) return (long)i;
            }
        }
        if (sz > limit || out->len > limit - sz) return -2;
        if (len - i < sz + 2) return 0;
        ubuf_add(out, p + i, sz);
        i += sz;
        if (p[i] != '\r' || p[i + 1] != '\n') return -1;
        i += 2;
    }
}

int http_parse(UConn* c, UReq* req, UResp* err) {
    memset(req, 0, sizeof *req);
    char* buf = c->in.data;
    size_t len = c->in.len;
    if (!len) return 0;
    char* he = memmem(buf, len, "\r\n\r\n", 4);
    if (!he) {
        if (len > g_cfg.max_header) { err_simple(err, 431, "Request Header Fields Too Large"); return -1; }
        return 0;
    }
    size_t hlen = (size_t)(he - buf);
    if (hlen > g_cfg.max_header) { err_simple(err, 431, "Request Header Fields Too Large"); return -1; }

    req->mem = malloc(hlen + 1);
    memcpy(req->mem, buf, hlen); req->mem[hlen] = 0;
    char* m = req->mem;

    /* request line */
    char* eol = strstr(m, "\r\n"); if (eol) *eol = 0;
    char* p = m;
    char* meth = p; while (*p && (isalnum((unsigned char)*p) || *p == '_')) p++;
    if (p == meth || (*p != ' ' && *p != '\t')) goto malformed;
    *p++ = 0; while (*p == ' ' || *p == '\t') p++;
    char* target = p; while (*p && !isspace((unsigned char)*p)) p++;
    if (p == target || !*p) goto malformed;
    *p++ = 0; while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "HTTP/", 5) || !isdigit((unsigned char)p[5]) || p[6] != '.' || !isdigit((unsigned char)p[7])) goto malformed;
    req->version[0] = p[5]; req->version[1] = '.'; req->version[2] = p[7]; req->version[3] = 0;
    req->method = meth; req->uri = target;

    static const char* known[] = { "GET","HEAD","POST","PUT","DELETE","PATCH","OPTIONS","TRACE","CONNECT", NULL };
    int ok = 0, wrongcase = 0;
    for (int i = 0; known[i]; i++) { if (!strcmp(meth, known[i])) ok = 1; else if (!strcasecmp(meth, known[i])) wrongcase = 1; }
    if (!ok && wrongcase) { err_simple(err, 501, "Not Implemented"); return -1; }

    char* q = strchr(target, '?');
    size_t plen = q ? (size_t)(q - target) : strlen(target);
    req->query = q ? q + 1 : target + strlen(target);
    req->path = decode_path(target, plen, &req->path_nul);

    /* headers */
    int hosts = 0;
    char* line = eol ? eol + 2 : m + hlen;
    int last = -1;
    while (line && line < m + hlen) {
        char* le = strstr(line, "\r\n");
        if (le) *le = 0;
        if ((*line == ' ' || *line == '\t') && last >= 0) {
            /* obs-fold: append to the previous value */
            char* v = line; while (*v == ' ' || *v == '\t') v++;
            size_t vl = strlen(v); while (vl && (v[vl-1] == ' ' || v[vl-1] == '\t')) v[--vl] = 0;
            UBuf nb = {0}; ubuf_adds(&nb, req->h[last].value); ubuf_add(&nb, " ", 1); ubuf_adds(&nb, v);
            req->h[last].value = keep(req, nb.data);
        } else {
            char* colon = strchr(line, ':');
            if (colon && colon != line) {
                *colon = 0;
                for (char* k = line; *k; k++) if (!is_tchar((unsigned char)*k)) { err_simple(err, 400, "Bad Request: Invalid header name"); return -1; }
                char* v = colon + 1; while (*v == ' ' || *v == '\t') v++;
                size_t vl = strlen(v); while (vl && (v[vl-1] == ' ' || v[vl-1] == '\t')) v[--vl] = 0;
                if (req->nraw < UREQ_MAX_HEADERS) { req->raw[req->nraw].name = line; req->raw[req->nraw].value = v; req->nraw++; }
                for (char* k = line; *k; k++) *k = (char)tolower((unsigned char)*k);
                if (!strcmp(line, "host") && ++hosts > 1) { err_simple(err, 400, "Bad Request: Multiple Host headers"); return -1; }
                int found = -1;
                for (int i = 0; i < req->nh; i++) if (!strcmp(req->h[i].name, line)) { found = i; break; }
                if (found >= 0) {
                    UBuf nb = {0}; ubuf_adds(&nb, req->h[found].value); ubuf_add(&nb, ", ", 2); ubuf_adds(&nb, v);
                    req->h[found].value = keep(req, nb.data);
                    last = found;
                } else if (req->nh < UREQ_MAX_HEADERS) {
                    req->h[req->nh].name = line; req->h[req->nh].value = v; last = req->nh++;
                }
            }
        }
        line = le ? le + 2 : NULL;
    }
    /* original-case names: the lower-casing above edited them in place, so
       recover the case from the untouched input buffer */
    for (int i = 0; i < req->nraw; i++) {
        size_t off = (size_t)(req->raw[i].name - m);
        size_t nl = strlen(req->raw[i].name);
        char* orig = malloc(nl + 1); memcpy(orig, buf + off, nl); orig[nl] = 0;
        req->raw[i].name = keep(req, orig);
    }

    if (!strcmp(req->version, "1.0") && !ureq_header(req, "connection") && req->nh < UREQ_MAX_HEADERS) {
        req->h[req->nh].name = "connection"; req->h[req->nh].value = "close"; req->nh++;
    }

    /* ── request smuggling / injection checks ────────────────────── */

    /* NULL bytes anywhere in the header block */
    if (memchr(buf, 0, hlen)) { err_simple(err, 400, "Bad Request: NULL byte in headers"); return -1; }

    /* Scan header values for bare CR or LF (CRLF injection) and header
       names for non-ASCII bytes.  Also count Content-Length headers to
       catch duplicates — the combining loop above merges them into one
       comma-separated value, but CL MUST NOT be repeated with different
       values (RFC 9110 §8.6). */
    int cl_count = 0;
    for (int i = 0; i < req->nh; i++) {
        /* non-ASCII in header name */
        for (const char* k = req->h[i].name; *k; k++) {
            if ((unsigned char)*k > 127) { err_simple(err, 400, "Bad Request: Non-ASCII header name"); return -1; }
        }
        /* bare CR or LF in header value (obs-fold already joined) */
        for (const char* v = req->h[i].value; *v; v++) {
            if (*v == '\r' || *v == '\n') { err_simple(err, 400, "Bad Request: Bare CR/LF in header value"); return -1; }
        }
        if (!strcmp(req->h[i].name, "content-length")) {
            cl_count++;
            /* check for comma (merged duplicate values) */
            if (strchr(req->h[i].value, ',')) { err_simple(err, 400, "Bad Request: Duplicate Content-Length"); return -1; }
        }
    }

    /* path traversal: reject ".." segments after decode */
    if (req->path) {
        const char* seg = req->path;
        while (*seg) {
            if (seg[0] == '.' && seg[1] == '.' && (seg[2] == '/' || seg[2] == 0)) {
                err_simple(err, 400, "Bad Request: Path traversal"); return -1;
            }
            const char* sl = strchr(seg, '/');
            seg = sl ? sl + 1 : seg + strlen(seg);
        }
    }

    /* body */
    size_t body_start = hlen + 4;
    const char* te = ureq_header(req, "transfer-encoding");
    const char* cl = ureq_header(req, "content-length");

    /* mixed Content-Length + Transfer-Encoding → smuggling vector */
    if (te && cl) { err_simple(err, 400, "Bad Request: Ambiguous framing"); return -1; }

    /* Transfer-Encoding must be exactly "chunked" (no trailing text like "chunked, identity") */
    if (te && strcasecmp(te, "chunked")) { err_simple(err, 400, "Bad Request: Unsupported Transfer-Encoding"); return -1; }
    size_t consumed;
    if (te) {  /* already validated as exactly "chunked" */
        UBuf b = {0};
        long r = dechunk(buf + body_start, len - body_start, &b, g_cfg.max_post);
        if (r == -2) { ubuf_free(&b); err_simple(err, 413, "Payload Too Large"); return -1; }
        if (r < 0) { ubuf_free(&b); err_simple(err, 400, "Bad Request"); return -1; }
        if (r == 0) {
            ubuf_free(&b);
            if (len - body_start > g_cfg.max_post + 65536) { err_simple(err, 413, "Payload Too Large"); return -1; }
            goto incomplete;
        }
        req->bodymem = b.data ? b.data : calloc(1, 1); req->body = req->bodymem; req->body_len = b.len;
        consumed = body_start + (size_t)r;
    } else if (cl) {
        char* e; unsigned long long n = strtoull(cl, &e, 10);
        if (e == cl) { err_simple(err, 400, "Bad Request"); return -1; }
        if (n > g_cfg.max_post) { err_simple(err, 413, "Payload Too Large"); return -1; }
        if (len - body_start < n) goto incomplete;
        req->bodymem = malloc(n + 1); memcpy(req->bodymem, buf + body_start, n); req->bodymem[n] = 0;
        req->body = req->bodymem; req->body_len = n;
        consumed = body_start + n;
    } else {
        req->bodymem = calloc(1, 1); req->body = req->bodymem;
        consumed = body_start;
    }
    ubuf_consume(&c->in, consumed);

    const char* conn = ureq_header(req, "connection");
    req->keep_alive = !(conn && strcasecmp(conn, "close") == 0);
    snprintf(req->remote_ip, sizeof req->remote_ip, "%s", c->ip);
    req->remote_port = c->port;
    req->local_port = c->local_port;
    return 1;

incomplete:
    ureq_free(req);
    return 0;
malformed:
    err_simple(err, 400, "Bad Request");
    return -1;
}
