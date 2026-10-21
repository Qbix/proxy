/* fastcgi.c — FastCGI binary protocol for forwarding to PHP-FPM.
 *
 * Implements just enough of the spec to act as a client (the proxy
 * side of a responder transaction).  The record format is:
 *
 *   byte  version      = 1
 *   byte  type
 *   u16   requestId    (big-endian)
 *   u16   contentLength
 *   byte  paddingLength
 *   byte  reserved
 *   [contentLength bytes of content]
 *   [paddingLength bytes of padding]
 *
 * Record types we use:
 *   1 = BEGIN_REQUEST   (we send)
 *   3 = END_REQUEST     (we read)
 *   4 = PARAMS          (we send)
 *   5 = STDIN           (we send)
 *   6 = STDOUT          (we read)
 *   7 = STDERR          (we read, logged)
 *
 * Reference: https://fastcgi-archives.github.io/FastCGI_Specification.html
 */
#include "userver.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <ctype.h>

/* ── record types ────────────────────────────────────────────────── */
#define FCGI_BEGIN_REQUEST   1
#define FCGI_END_REQUEST     3
#define FCGI_PARAMS          4
#define FCGI_STDIN           5
#define FCGI_STDOUT          6
#define FCGI_STDERR          7

#define FCGI_RESPONDER       1
#define FCGI_MAX_CONTENT     65535
#define FCGI_REQUEST_ID      1   /* we use a single request per connection */

/* ── wire helpers ────────────────────────────────────────────────── */

static void put_u16be(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

static uint16_t get_u16be(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

/* Write a complete FCGI record header into buf (8 bytes). */
static void fcgi_header(uint8_t* buf, uint8_t type, uint16_t content_len) {
    buf[0] = 1;   /* version */
    buf[1] = type;
    put_u16be(buf + 2, FCGI_REQUEST_ID);
    put_u16be(buf + 4, content_len);
    buf[6] = 0;   /* padding */
    buf[7] = 0;   /* reserved */
}

/* Send all bytes, retrying on partial writes. */
static int send_all(int fd, const void* data, size_t n) {
    const uint8_t* p = data;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return -1;
        }
        p += w; n -= (size_t)w;
    }
    return 0;
}

/* Send a typed record (content may be NULL for zero-length). */
static int send_record(int fd, uint8_t type, const void* content, uint16_t len) {
    uint8_t hdr[8];
    fcgi_header(hdr, type, len);
    if (send_all(fd, hdr, 8)) return -1;
    if (len > 0 && send_all(fd, content, len)) return -1;
    return 0;
}

/* Send BEGIN_REQUEST (role=RESPONDER, flags=0 → close connection when done). */
static int send_begin_request(int fd) {
    uint8_t body[8] = {0};
    put_u16be(body, FCGI_RESPONDER);  /* role */
    /* body[2] = flags = 0 (FCGI_KEEP_CONN not set) */
    return send_record(fd, FCGI_BEGIN_REQUEST, body, 8);
}

/* Encode one FCGI name-value pair into a buffer. */
static void encode_param(UBuf* buf, const char* name, size_t nlen, const char* value, size_t vlen) {
    /* Length encoding: < 128 = 1 byte, >= 128 = 4 bytes with high bit set */
    if (nlen < 128) {
        uint8_t b = (uint8_t)nlen;
        ubuf_add(buf, &b, 1);
    } else {
        uint8_t b[4];
        b[0] = (uint8_t)(0x80 | ((nlen >> 24) & 0x7f));
        b[1] = (uint8_t)((nlen >> 16) & 0xff);
        b[2] = (uint8_t)((nlen >> 8) & 0xff);
        b[3] = (uint8_t)(nlen & 0xff);
        ubuf_add(buf, b, 4);
    }
    if (vlen < 128) {
        uint8_t b = (uint8_t)vlen;
        ubuf_add(buf, &b, 1);
    } else {
        uint8_t b[4];
        b[0] = (uint8_t)(0x80 | ((vlen >> 24) & 0x7f));
        b[1] = (uint8_t)((vlen >> 16) & 0xff);
        b[2] = (uint8_t)((vlen >> 8) & 0xff);
        b[3] = (uint8_t)(vlen & 0xff);
        ubuf_add(buf, b, 4);
    }
    ubuf_add(buf, name, nlen);
    ubuf_add(buf, value, vlen);
}

/* Add a string param. */
static void add_param(UBuf* buf, const char* name, const char* value) {
    if (!value) value = "";
    encode_param(buf, name, strlen(name), value, strlen(value));
}

/* Send PARAMS records (split across multiple records if needed). */
static int send_params(int fd, UBuf* params) {
    const uint8_t* p = (const uint8_t*)params->data;
    size_t left = params->len;
    while (left > 0) {
        uint16_t chunk = left > FCGI_MAX_CONTENT ? FCGI_MAX_CONTENT : (uint16_t)left;
        if (send_record(fd, FCGI_PARAMS, p, chunk)) return -1;
        p += chunk; left -= chunk;
    }
    /* Empty PARAMS record signals end of params */
    return send_record(fd, FCGI_PARAMS, NULL, 0);
}

/* Send STDIN records. */
static int send_stdin(int fd, const char* body, size_t body_len) {
    const uint8_t* p = (const uint8_t*)body;
    size_t left = body_len;
    while (left > 0) {
        uint16_t chunk = left > FCGI_MAX_CONTENT ? FCGI_MAX_CONTENT : (uint16_t)left;
        if (send_record(fd, FCGI_STDIN, p, chunk)) return -1;
        p += chunk; left -= chunk;
    }
    /* Empty STDIN signals end of input */
    return send_record(fd, FCGI_STDIN, NULL, 0);
}

/* ── reading the response ────────────────────────────────────────── */

/* Read exactly n bytes from fd. */
static int recv_all(int fd, void* buf, size_t n) {
    uint8_t* p = buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return -1;
        }
        p += r; n -= (size_t)r;
    }
    return 0;
}

/* Maximum response size from a backend (64 MiB).  Prevents a
   misbehaving backend from exhausting proxy memory. */
#define MAX_RESPONSE_BYTES (64 * 1024 * 1024)

/* Read records from the backend until END_REQUEST.  Collects STDOUT
   into `out` and logs STDERR. */
static int read_response(int fd, UBuf* out) {
    for (;;) {
        uint8_t hdr[8];
        if (recv_all(fd, hdr, 8)) return -1;

        uint8_t type = hdr[1];
        uint16_t clen = get_u16be(hdr + 4);
        uint8_t pad = hdr[6];

        /* Read content + padding */
        uint8_t* content = NULL;
        if (clen + pad > 0) {
            content = malloc(clen + pad);
            if (recv_all(fd, content, clen + pad)) { free(content); return -1; }
        }

        switch (type) {
        case FCGI_STDOUT:
            if (clen > 0) {
                if (out->len + clen > MAX_RESPONSE_BYTES) {
                    free(content);
                    return -1;  /* response too large */
                }
                ubuf_add(out, content, clen);
            }
            break;
        case FCGI_STDERR:
            if (clen > 0) {
                /* Log stderr from PHP, but don't forward to client */
                char* msg = malloc(clen + 1);
                memcpy(msg, content, clen); msg[clen] = 0;
                fprintf(stderr, "[fastcgi-stderr] %s\n", msg);
                free(msg);
            }
            break;
        case FCGI_END_REQUEST:
            free(content);
            return 0;  /* done */
        }
        free(content);
    }
}

/* Parse CGI-style response (headers + blank line + body) from PHP-FPM
   output into a UResp. */
static int parse_cgi_response(UBuf* raw, UResp* resp) {
    uresp_init(resp);

    char* data = raw->data;
    size_t len = raw->len;

    /* Find header/body separator */
    char* sep = memmem(data, len, "\r\n\r\n", 4);
    if (!sep) {
        /* PHP might use just \n\n */
        sep = memmem(data, len, "\n\n", 2);
        if (!sep) {
            /* No headers — entire output is body */
            resp->status = 200;
            ubuf_add(&resp->body, data, len);
            return 0;
        }
    }

    int sep_len = (sep[0] == '\r') ? 4 : 2;

    /* Parse headers */
    resp->status = 200;  /* default unless Status: header */
    char* line = data;
    while (line < sep) {
        char* eol = memmem(line, (size_t)(sep - line), (sep[0] == '\r') ? "\r\n" : "\n",
                           (sep[0] == '\r') ? 2 : 1);
        if (!eol) eol = sep;
        size_t ll = (size_t)(eol - line);

        /* Parse "Name: value" */
        char* colon = memchr(line, ':', ll);
        if (colon) {
            *colon = 0;
            char* v = colon + 1;
            while (*v == ' ') v++;
            size_t vl = ll - (size_t)(v - line);

            if (!strcasecmp(line, "status")) {
                resp->status = atoi(v);
            } else {
                /* Copy as a response header */
                char name[128], val[4096];
                snprintf(name, sizeof name, "%s", line);
                snprintf(val, sizeof val, "%.*s", (int)vl, v);
                uresp_header(resp, name, val);
                if (!strcasecmp(name, "content-type")) resp->has_ctype = 1;
            }
        }

        line = eol + ((sep[0] == '\r') ? 2 : 1);
    }

    /* Body is everything after the separator */
    char* body_start = sep + sep_len;
    size_t body_len = len - (size_t)(body_start - data);
    if (body_len > 0) ubuf_add(&resp->body, body_start, body_len);

    return 0;
}

/* ── public API ──────────────────────────────────────────────────── */

int fastcgi_forward(int sock_fd, UReq* req, UResp* resp,
                    const char* document_root, const char* script_filename) {
    /* Send BEGIN_REQUEST */
    if (send_begin_request(sock_fd)) goto err;

    /* Build PARAMS */
    UBuf params = {0};
    add_param(&params, "REQUEST_METHOD", req->method);
    add_param(&params, "REQUEST_URI", req->uri);
    add_param(&params, "QUERY_STRING", req->query);
    add_param(&params, "DOCUMENT_ROOT", document_root);
    add_param(&params, "SCRIPT_FILENAME", script_filename);
    add_param(&params, "SERVER_PROTOCOL", "HTTP/1.1");
    add_param(&params, "SERVER_NAME", ureq_header(req, "host"));
    add_param(&params, "REMOTE_ADDR", req->remote_ip);
    add_param(&params, "HTTPS", req->tls ? "on" : "");

    char portbuf[8];
    snprintf(portbuf, sizeof portbuf, "%d", req->local_port);
    add_param(&params, "SERVER_PORT", portbuf);

    char rportbuf[8];
    snprintf(rportbuf, sizeof rportbuf, "%d", req->remote_port);
    add_param(&params, "REMOTE_PORT", rportbuf);

    /* Content-Type and Content-Length */
    const char* ct = ureq_header(req, "content-type");
    if (ct) add_param(&params, "CONTENT_TYPE", ct);
    if (req->body_len > 0) {
        char clbuf[32];
        snprintf(clbuf, sizeof clbuf, "%zu", req->body_len);
        add_param(&params, "CONTENT_LENGTH", clbuf);
    }

    /* Forward remaining headers as HTTP_* variables */
    for (int i = 0; i < req->nh; i++) {
        const char* name = req->h[i].name;
        /* Skip headers already sent as specific params */
        if (!strcmp(name, "content-type") || !strcmp(name, "content-length")) continue;

        /* Build HTTP_NAME (uppercase, hyphens to underscores) */
        char envname[256];
        memcpy(envname, "HTTP_", 5);
        size_t j = 5;
        for (const char* c = name; *c && j < sizeof(envname) - 1; c++) {
            envname[j++] = (*c == '-') ? '_' : (char)toupper((unsigned char)*c);
        }
        envname[j] = 0;
        add_param(&params, envname, req->h[i].value);
    }

    if (send_params(sock_fd, &params)) { ubuf_free(&params); goto err; }
    ubuf_free(&params);

    /* Send STDIN (the request body) */
    if (send_stdin(sock_fd, req->body, req->body_len)) goto err;

    /* Read the response */
    UBuf raw = {0};
    if (read_response(sock_fd, &raw)) { ubuf_free(&raw); goto err; }

    /* Parse CGI response into UResp */
    if (parse_cgi_response(&raw, resp)) { ubuf_free(&raw); goto err; }
    ubuf_free(&raw);

    return 1;

err:
    uresp_init(resp);
    resp->status = 502;
    resp->close = 1;
    uresp_header(resp, "Content-Type", "text/plain; charset=utf-8");
    ubuf_adds(&resp->body, "Bad Gateway: FastCGI backend error");
    return 1;  /* still "done" — we have an error response */
}
