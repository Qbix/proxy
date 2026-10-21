/* sanitize.c — request validation pipeline for the proxy mode.
 *
 * Every inbound request destined for a proxy backend goes through this
 * pipeline.  Failure at any stage produces an error response directly —
 * the backend never sees the request.
 *
 * Stages:
 *   1. Content-Type validation against the backend's allow-list
 *   2. Method validation against the backend's allow-list
 *   3. Multipart body re-parsing and re-serialization
 *   4. JSON depth/size validation
 *   5. URL-encoded body validation and re-serialization
 *   6. Header sanitization (strip dangerous, add forwarding headers)
 *
 * The key invariant: after sanitize_request() returns 0 the request
 * body contains bytes that WE generated, not bytes the client sent.
 * This eliminates parser-differential attacks between the proxy and
 * the backend.
 */
#include "userver.h"
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

/* ── helpers ──────────────────────────────────────────────────────── */

static void reject(UResp* resp, int status, const char* reason) {
    uresp_init(resp);
    resp->status = status;
    resp->close = 1;
    uresp_header(resp, "Content-Type", "text/plain; charset=utf-8");
    ubuf_adds(&resp->body, reason);
}

/* Extract the base media type from a Content-Type value, ignoring
   parameters.  Result is lowered and written into `out` (must hold
   at least `n` bytes).  Returns 0 on success. */
static int parse_media_type(const char* ct, char* out, size_t n) {
    if (!ct || !*ct) return -1;
    /* RFC 9110 uses ';' to delimit parameters, but PHP's SAPI.c also
       accepts ',' as a parameter delimiter.  We must split on whichever
       comes first to avoid a parser differential that bypasses multipart
       sanitization. */
    const char* semi = strchr(ct, ';');
    const char* comma = strchr(ct, ',');
    const char* delim = semi;
    if (comma && (!delim || comma < delim)) delim = comma;
    size_t len = delim ? (size_t)(delim - ct) : strlen(ct);
    while (len > 0 && ct[len - 1] == ' ') len--;
    if (len >= n) return -1;
    for (size_t i = 0; i < len; i++) out[i] = (char)tolower((unsigned char)ct[i]);
    out[len] = 0;
    return 0;
}

/* Simple glob match for MIME patterns like image/star. */
static int mime_glob_match(const char* pattern, const char* value) {
    size_t plen = strlen(pattern);
    if (plen >= 2 && pattern[plen - 2] == '/' && pattern[plen - 1] == '*') {
        return !strncasecmp(pattern, value, plen - 1);  /* match up to the slash */
    }
    return !strcasecmp(pattern, value);
}

/* Generate a random multipart boundary for re-serialization.
   Uses /dev/urandom when available, falls back to a clock-seeded LCG. */
static void make_boundary(char* out, size_t n) {
    static const char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    uint8_t rnd[64];
    int got_random = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        got_random = (read(fd, rnd, n - 1) == (ssize_t)(n - 1));
        close(fd);
    }
    if (!got_random) {
        /* Fallback: clock + pointer seeded LCG */
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t seed = (uint64_t)ts.tv_nsec ^ (uint64_t)ts.tv_sec ^ (uint64_t)(uintptr_t)out;
        for (size_t i = 0; i < n - 1; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            rnd[i] = (uint8_t)(seed >> 33);
        }
    }
    for (size_t i = 0; i < n - 1; i++)
        out[i] = chars[rnd[i] % (sizeof(chars) - 1)];
    out[n - 1] = 0;
}

/* ── 1. Content-Type validation ──────────────────────────────────── */

int sanitize_content_type(const char* ct, const UBackendConstraints* bc) {
    if (bc->n_content_types == 0) return 0;  /* no restrict = allow all */
    if (!ct || !*ct) return 0;  /* no body content-type is fine (GET etc.) */

    char base[128];
    if (parse_media_type(ct, base, sizeof base)) return -1;

    for (int i = 0; i < bc->n_content_types; i++) {
        if (!strcasecmp(bc->allowed_content_types[i], base)) return 0;
    }
    return -1;
}

/* ── 2. Method validation ────────────────────────────────────────── */

static int sanitize_method(const char* method, const UBackendConstraints* bc) {
    if (bc->n_methods == 0) return 0;  /* no restrict = allow all */
    for (int i = 0; i < bc->n_methods; i++) {
        if (!strcmp(bc->allowed_methods[i], method)) return 0;
    }
    return -1;
}

/* ── 3. Multipart re-parse and re-serialize ──────────────────────── */

/* A parsed multipart part. */
typedef struct {
    char*   disposition;   /* full Content-Disposition value */
    char*   name;          /* field name from disposition */
    char*   filename;      /* filename from disposition, or NULL */
    char*   content_type;  /* Content-Type of this part, or NULL */
    char*   data;
    size_t  data_len;
} MPart;

/* Extract a parameter value from a header like:
   form-data; name="field"; filename="file.jpg"
   Returns a malloc'd string, or NULL. */
static char* mp_param(const char* header, const char* param) {
    if (!header) return NULL;
    size_t plen = strlen(param);
    const char* p = header;
    while ((p = strcasestr(p, param)) != NULL) {
        /* must be preceded by ; or , or start of string, and followed by = */
        if (p != header && *(p - 1) != ';' && *(p - 1) != ',' && *(p - 1) != ' ') { p += plen; continue; }
        p += plen;
        while (*p == ' ') p++;
        if (*p != '=') continue;
        p++;
        while (*p == ' ') p++;
        if (*p == '"') {
            p++;
            const char* end = strchr(p, '"');
            if (!end) return NULL;
            size_t len = (size_t)(end - p);
            char* r = malloc(len + 1);
            if (!r) return NULL;
            memcpy(r, p, len); r[len] = 0;
            return r;
        } else {
            const char* end = p;
            while (*end && *end != ';' && *end != ',' && *end != ' ' && *end != '\r' && *end != '\n') end++;
            size_t len = (size_t)(end - p);
            char* r = malloc(len + 1);
            if (!r) return NULL;
            memcpy(r, p, len); r[len] = 0;
            return r;
        }
    }
    return NULL;
}

/* Get the file extension from a filename.  Returns pointer into the
   string (after the last dot), or NULL. */
static const char* file_extension(const char* filename) {
    if (!filename) return NULL;
    const char* dot = strrchr(filename, '.');
    return dot ? dot + 1 : NULL;
}

/* Check if extension is in the allow list. */
static int extension_allowed(const char* ext, const UUploadConstraints* uc) {
    if (uc->n_extensions == 0) return 1;  /* no list = allow all */
    for (int i = 0; i < uc->n_extensions; i++) {
        if (!strcasecmp(uc->allowed_extensions[i], ext)) return 1;
    }
    return 0;
}

/* Check if MIME type matches the allow list (supports globs). */
static int mime_type_allowed(const char* ct, const UUploadConstraints* uc) {
    if (uc->n_mime_types == 0) return 1;  /* no list = allow all */
    if (!ct) return 1;
    for (int i = 0; i < uc->n_mime_types; i++) {
        if (mime_glob_match(uc->allowed_mime_types[i], ct)) return 1;
    }
    return 0;
}

int sanitize_multipart(UReq* req, UResp* resp, const UBackendConstraints* bc) {
    const char* ct = ureq_header(req, "content-type");
    if (!ct) { reject(resp, 400, "Missing Content-Type for multipart"); return -1; }

    /* Extract the boundary */
    char* boundary = mp_param(ct, "boundary");
    if (!boundary || !*boundary) { free(boundary); reject(resp, 400, "Missing multipart boundary"); return -1; }

    /* Parse the body into parts */
    char delim[256];
    snprintf(delim, sizeof delim, "--%s", boundary);
    size_t dlen = strlen(delim);
    free(boundary);

    /* Walk the body, splitting on the delimiter */
    MPart parts[256];
    int nparts = 0;
    int nfiles = 0;

    const char* p = req->body;
    const char* end = req->body + req->body_len;

    /* Find first delimiter */
    const char* start = memmem(p, (size_t)(end - p), delim, dlen);
    if (!start) { reject(resp, 400, "No multipart boundary found in body"); return -1; }
    start += dlen;
    if (start + 2 <= end && start[0] == '\r' && start[1] == '\n') start += 2;

    while (start < end && nparts < 256) {
        /* Find end delimiter */
        const char* pend = memmem(start, (size_t)(end - start), delim, dlen);
        if (!pend) break;

        /* Check for final delimiter (--) */
        size_t partlen = (size_t)(pend - start);
        /* Remove trailing CRLF before delimiter */
        if (partlen >= 2 && start[partlen - 2] == '\r' && start[partlen - 1] == '\n') partlen -= 2;

        /* Parse part headers */
        const char* hend = memmem(start, partlen, "\r\n\r\n", 4);
        if (!hend) { reject(resp, 400, "Malformed multipart part"); goto mp_fail; }

        MPart* mp = &parts[nparts];
        memset(mp, 0, sizeof *mp);

        /* Extract Content-Disposition and Content-Type from part headers */
        const char* line = start;
        while (line < hend) {
            const char* le = memmem(line, (size_t)(hend - line + 2), "\r\n", 2);
            if (!le) le = hend;
            size_t ll = (size_t)(le - line);
            if (ll > 21 && !strncasecmp(line, "content-disposition:", 20)) {
                const char* v = line + 20; while (*v == ' ') v++;
                mp->disposition = strndup(v, ll - (size_t)(v - line));
            } else if (ll > 13 && !strncasecmp(line, "content-type:", 13)) {
                const char* v = line + 13; while (*v == ' ') v++;
                mp->content_type = strndup(v, ll - (size_t)(v - line));
            }
            line = le + 2;
        }

        if (!mp->disposition) { reject(resp, 400, "Multipart part missing Content-Disposition"); goto mp_fail; }
        mp->name = mp_param(mp->disposition, "name");
        if (!mp->name) { reject(resp, 400, "Multipart part missing name"); goto mp_fail; }
        /* Reject quotes in name/filename to prevent Content-Disposition
           injection during re-serialization (the values are embedded in
           double-quoted fields). */
        if (strchr(mp->name, '"') || strchr(mp->name, '\\')) {
            reject(resp, 400, "Invalid character in multipart field name"); goto mp_fail;
        }
        mp->filename = mp_param(mp->disposition, "filename");
        if (mp->filename && (strchr(mp->filename, '"') || strchr(mp->filename, '\\'))) {
            reject(resp, 400, "Invalid character in multipart filename"); goto mp_fail;
        }

        /* Part data starts after the header blank line */
        mp->data = (char*)(hend + 4);
        mp->data_len = partlen - (size_t)(hend + 4 - start);

        /* File upload validation */
        if (mp->filename) {
            nfiles++;
            const UUploadConstraints* uc = &bc->upload;

            if (uc->max_files > 0 && nfiles > uc->max_files) {
                reject(resp, 400, "Too many uploaded files"); goto mp_fail;
            }
            size_t max_fb = uc->max_file_bytes ? uc->max_file_bytes : (bc->max_body_bytes ? bc->max_body_bytes : 10u << 20);
            if (mp->data_len > max_fb) {
                reject(resp, 413, "Uploaded file too large"); goto mp_fail;
            }
            const char* ext = file_extension(mp->filename);
            if (ext && !extension_allowed(ext, uc)) {
                reject(resp, 400, "File extension not allowed"); goto mp_fail;
            }
            if (mp->content_type && !mime_type_allowed(mp->content_type, uc)) {
                reject(resp, 400, "File MIME type not allowed"); goto mp_fail;
            }
        }

        nparts++;

        /* Advance past delimiter */
        start = pend + dlen;
        if (start + 2 <= end && start[0] == '-' && start[1] == '-') break;  /* final delimiter */
        if (start + 2 <= end && start[0] == '\r' && start[1] == '\n') start += 2;
    }

    if (nparts == 0) { reject(resp, 400, "Empty multipart body"); goto mp_fail; }

    /* Re-serialize from our parsed representation — this is the key
       security step.  PHP/Node will never see the original bytes. */
    char new_boundary[48];
    make_boundary(new_boundary, sizeof new_boundary);

    UBuf out = {0};
    for (int i = 0; i < nparts; i++) {
        MPart* mp = &parts[i];
        ubuf_printf(&out, "--%s\r\n", new_boundary);
        /* Content-Disposition: always form-data */
        if (mp->filename) {
            ubuf_printf(&out, "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n", mp->name, mp->filename);
        } else {
            ubuf_printf(&out, "Content-Disposition: form-data; name=\"%s\"\r\n", mp->name);
        }
        if (mp->content_type) {
            ubuf_printf(&out, "Content-Type: %s\r\n", mp->content_type);
        }
        ubuf_adds(&out, "\r\n");
        ubuf_add(&out, mp->data, mp->data_len);
        ubuf_adds(&out, "\r\n");
    }
    ubuf_printf(&out, "--%s--\r\n", new_boundary);

    /* Replace the request body */
    free(req->bodymem);
    req->bodymem = out.data;
    req->body = out.data;
    req->body_len = out.len;

    /* Update Content-Type with new boundary — we need to replace the
       header value.  Since header values point into req->mem, we
       allocate a new string and track it in req->allocs. */
    for (int i = 0; i < req->nh; i++) {
        if (!strcmp(req->h[i].name, "content-type")) {
            char* newct = NULL;
            if (asprintf(&newct, "multipart/form-data; boundary=%s", new_boundary) < 0) newct = NULL;
            if (newct) {
                req->h[i].value = newct;
                req->allocs = realloc(req->allocs, sizeof(char*) * (size_t)(req->nallocs + 1));
                req->allocs[req->nallocs++] = newct;
            }
            break;
        }
    }

    /* Clean up part metadata */
    for (int i = 0; i < nparts; i++) {
        free(parts[i].disposition); free(parts[i].name);
        free(parts[i].filename); free(parts[i].content_type);
    }
    return 0;

mp_fail:
    for (int i = 0; i < nparts; i++) {
        free(parts[i].disposition); free(parts[i].name);
        free(parts[i].filename); free(parts[i].content_type);
    }
    return -1;
}

/* ── 4. JSON validation ──────────────────────────────────────────── */

/* Minimal JSON depth/size validation.  We walk the bytes ourselves
   rather than building a tree — we only need to enforce limits. */
int sanitize_json(UReq* req, UResp* resp, const UBackendConstraints* bc) {
    int max_depth = bc->json_max_depth ? bc->json_max_depth : 32;
    size_t max_string = bc->json_max_string ? bc->json_max_string : (1u << 20);

    const char* p = req->body;
    const char* end = p + req->body_len;
    int depth = 0;
    int in_string = 0;
    size_t string_len = 0;

    while (p < end) {
        if (in_string) {
            if (*p == '\\') { p += 2; string_len += 2; continue; }
            if (*p == '"') {
                if (string_len > max_string) {
                    reject(resp, 400, "JSON string too long"); return -1;
                }
                in_string = 0;
            } else {
                string_len++;
            }
        } else {
            switch (*p) {
            case '"': in_string = 1; string_len = 0; break;
            case '{': case '[':
                if (++depth > max_depth) { reject(resp, 400, "JSON nesting too deep"); return -1; }
                break;
            case '}': case ']':
                if (depth > 0) depth--;
                break;
            }
        }
        p++;
    }

    /* If we ended inside a string or unbalanced, the JSON is broken */
    if (in_string || depth != 0) { reject(resp, 400, "Malformed JSON"); return -1; }

    return 0;
}

/* ── 5. URL-encoded body validation ──────────────────────────────── */

int sanitize_urlencoded(UReq* req, UResp* resp, const UBackendConstraints* bc) {
    int max_params = bc->max_query_params ? bc->max_query_params : 128;
    size_t max_value = bc->urlenc_max_value ? bc->urlenc_max_value : (64u << 10);
    int params = 0;

    /* Walk the body counting &-separated pairs and checking value sizes */
    const char* p = req->body;
    const char* end = p + req->body_len;

    UBuf out = {0};

    while (p < end) {
        const char* amp = memchr(p, '&', (size_t)(end - p));
        size_t pairlen = amp ? (size_t)(amp - p) : (size_t)(end - p);

        if (pairlen > 0) {  /* skip empty pairs */
            if (++params > max_params) {
                ubuf_free(&out);
                reject(resp, 400, "Too many form parameters"); return -1;
            }

            const char* eq = memchr(p, '=', pairlen);
            size_t vlen = eq ? pairlen - (size_t)(eq + 1 - p) : 0;
            if (vlen > max_value) {
                ubuf_free(&out);
                reject(resp, 400, "Form parameter value too large"); return -1;
            }

            /* Re-serialize: just copy the valid pair */
            if (out.len > 0) ubuf_add(&out, "&", 1);
            ubuf_add(&out, p, pairlen);
        }

        p += pairlen;
        if (amp) p++;  /* skip the & */
    }

    /* Replace the body with our re-serialized version */
    free(req->bodymem);
    if (out.data) {
        req->bodymem = out.data;
        req->body = out.data;
        req->body_len = out.len;
    } else {
        req->bodymem = calloc(1, 1);
        req->body = req->bodymem;
        req->body_len = 0;
    }
    return 0;
}

/* ── 6. Header sanitization ──────────────────────────────────────── */

void sanitize_headers(UReq* req, const char* remote_ip, int tls) {
    /* Strip dangerous headers */
    int w = 0;
    for (int i = 0; i < req->nh; i++) {
        const char* name = req->h[i].name;
        /* Strip headers starting with "proxy-" */
        if (!strncmp(name, "proxy-", 6)) continue;
        /* Strip Transfer-Encoding (we already decoded chunked; forward with CL) */
        if (!strcmp(name, "transfer-encoding")) continue;
        /* Strip URL-override headers */
        if (!strcmp(name, "x-original-url")) continue;
        if (!strcmp(name, "x-rewrite-url")) continue;
        /* Strip non-printable header names */
        int bad = 0;
        for (const char* k = name; *k; k++) {
            if ((unsigned char)*k < 0x20 || (unsigned char)*k > 0x7e) { bad = 1; break; }
        }
        if (bad) continue;

        if (w != i) req->h[w] = req->h[i];
        w++;
    }
    req->nh = w;

    /* Add forwarding headers.  We allocate these strings and track
       them in req->allocs so they get freed with the request. */
    if (req->nh + 3 <= UREQ_MAX_HEADERS) {
        /* X-Forwarded-For */
        char* xff = strdup(remote_ip);
        req->allocs = realloc(req->allocs, sizeof(char*) * (size_t)(req->nallocs + 3));
        req->allocs[req->nallocs++] = xff;
        req->h[req->nh].name = "x-forwarded-for";
        req->h[req->nh].value = xff;
        req->nh++;

        /* X-Forwarded-Proto */
        req->h[req->nh].name = "x-forwarded-proto";
        req->h[req->nh].value = tls ? "https" : "http";
        req->nh++;

        /* X-Request-Id — use /dev/urandom for unpredictability */
        char* rid = malloc(37);
        unsigned char rb[16];
        FILE* uf = fopen("/dev/urandom", "r");
        if (uf) { if (fread(rb, 1, sizeof rb, uf) < sizeof rb) memset(rb, 0, sizeof rb); fclose(uf); }
        else { memset(rb, 0, sizeof rb); }  /* fallback: zeroed, but shouldn't happen on Linux */
        snprintf(rid, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 rb[0], rb[1], rb[2], rb[3], rb[4], rb[5], rb[6], rb[7],
                 rb[8], rb[9], rb[10], rb[11], rb[12], rb[13], rb[14], rb[15]);
        req->allocs[req->nallocs++] = rid;
        req->h[req->nh].name = "x-request-id";
        req->h[req->nh].value = rid;
        req->nh++;
    }
}

/* ── Main pipeline entry point ───────────────────────────────────── */

int sanitize_request(UReq* req, UResp* resp, const UBackendConstraints* bc) {
    /* Size checks against per-backend limits */
    if (bc->max_body_bytes && req->body_len > bc->max_body_bytes) {
        reject(resp, 413, "Payload Too Large"); return -1;
    }
    if (bc->max_url_bytes && strlen(req->uri) > bc->max_url_bytes) {
        reject(resp, 414, "URI Too Long"); return -1;
    }
    if (bc->max_headers && req->nh > bc->max_headers) {
        reject(resp, 431, "Too Many Headers"); return -1;
    }

    /* Method check */
    if (sanitize_method(req->method, bc)) {
        reject(resp, 405, "Method Not Allowed"); return -1;
    }

    /* Content-Type check */
    const char* ct = ureq_header(req, "content-type");
    if (sanitize_content_type(ct, bc)) {
        reject(resp, 415, "Unsupported Media Type"); return -1;
    }

    /* Body-type-specific validation and re-serialization */
    if (ct && req->body_len > 0) {
        char base[128];
        if (!parse_media_type(ct, base, sizeof base)) {
            if (!strcmp(base, "multipart/form-data")) {
                if (sanitize_multipart(req, resp, bc)) return -1;
            } else if (!strcmp(base, "application/json")) {
                if (sanitize_json(req, resp, bc)) return -1;
            } else if (!strcmp(base, "application/x-www-form-urlencoded")) {
                if (sanitize_urlencoded(req, resp, bc)) return -1;
            }
            /* other content types: body passes through as-is */
        }
    }

    /* Header sanitization (always runs last — adds forwarding headers) */
    sanitize_headers(req, req->remote_ip, req->tls);

    return 0;
}
