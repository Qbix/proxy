/* route.c — the request pipeline, in Qbix Server's order (handleRequest):
 *
 *   ?Q.clearCache · virtual hosts · built-in assets · /Q/ control
 *   endpoints · WebSocket upgrade · blocked paths · resolve the file ·
 *   directories (slash redirect, index.html / index.php, listing or 403) ·
 *   script.php/path/info · .php → PHP plane · static GET/HEAD · clean URLs →
 *   index.php · configured fallback · 404
 *
 * What is native here and what is not is listed in webserver-plan.md's
 * subsystem table; endpoints that belong to the embedded control plane
 * (Phase 3) answer as Qbix does when it has no panel configured.
 */
#include "userver.h"
#include <limits.h>
#include <ctype.h>
#include <dirent.h>

static const char* ERR_TITLE(int c) {
    switch (c) { case 403: return "Forbidden"; case 404: return "Not Found"; case 413: return "Payload Too Large";
    case 429: return "Too Many Requests"; case 500: return "Server Error"; case 502: return "Bad Gateway";
    case 503: return "Service Unavailable"; }
    return "Error";
}

static void html_escape(UBuf* out, const char* s) {
    for (; *s; s++) {
        switch (*s) {
        case '&': ubuf_adds(out, "&amp;"); break; case '<': ubuf_adds(out, "&lt;"); break;
        case '>': ubuf_adds(out, "&gt;"); break; case '"': ubuf_adds(out, "&quot;"); break;
        case '\'': ubuf_adds(out, "&#039;"); break; default: ubuf_add(out, s, 1);
        }
    }
}

/* Qbix's renderErrorPage, byte for byte, including the errors/<code>.html
   override in the document root. */
void route_error_page(UResp* resp, int code, const char* path) {
    resp->status = code;
    uresp_header(resp, "Content-Type", "text/html; charset=utf-8");
    char ov[PATH_MAX]; snprintf(ov, sizeof ov, "%serrors/%d.html", g_cfg.root, code);
    FILE* f = fopen(ov, "rb");
    if (f) { char b[8192]; size_t n; while ((n = fread(b, 1, sizeof b, f)) > 0) ubuf_add(&resp->body, b, n); fclose(f); return; }
    UBuf* o = &resp->body;
    ubuf_printf(o, "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>%d %s</title><style>"
        "*{margin:0;padding:0;box-sizing:border-box}"
        "body{font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif;"
        "min-height:100vh;display:flex;align-items:center;justify-content:center;"
        "background:#f8f9fa;color:#333}"
        ".c{text-align:center;padding:40px 20px;max-width:480px}"
        ".logo{width:40px;height:auto;margin-bottom:12px;opacity:.35}"
        ".n{font-size:100px;font-weight:700;color:#e0e0e0;line-height:1}"
        ".t{font-size:18px;margin:12px 0 8px;font-weight:600}"
        ".m{color:#888;line-height:1.5;font-size:14px}"
        ".m code{background:#eee;padding:2px 6px;border-radius:3px;font-size:13px;word-break:break-all}"
        ".b{margin-top:20px}"
        ".b a{color:#4a9eff;text-decoration:none;font-size:14px}"
        ".b a:hover{text-decoration:underline}"
        ".f{margin-top:28px;color:#ccc;font-size:11px}"
        "@media(max-width:500px){.n{font-size:72px}.t{font-size:16px}.m{font-size:13px}}"
        "</style></head><body><div class=\"c\">"
        "<img class=\"logo\" src=\"/Q/logo.png\" alt=\"\">"
        "<div class=\"n\">%d</div><div class=\"t\">%s</div><div class=\"m\">", code, ERR_TITLE(code), code, ERR_TITLE(code));
    switch (code) {
    case 403: ubuf_adds(o, "You don't have permission to access this resource."); break;
    case 404: ubuf_adds(o, "The page <code>"); html_escape(o, path ? path : ""); ubuf_adds(o, "</code> could not be found."); break;
    case 413: ubuf_adds(o, "The request body exceeds the maximum allowed size."); break;
    case 429: ubuf_adds(o, "Please slow down and try again later."); break;
    case 500: ubuf_adds(o, "Something went wrong. The server encountered an internal error."); break;
    case 502: ubuf_adds(o, "The server received an invalid response from an upstream server."); break;
    case 503: ubuf_adds(o, "The server is temporarily unavailable. Please try again later."); break;
    default:  ubuf_adds(o, "An unexpected error occurred.");
    }
    ubuf_adds(o, "</div><div class=\"b\"><a href=\"/\">\xe2\x86\x90 Back to home</a></div>"
                 "<div class=\"f\">Qbix Server</div></div></body></html>");
}

void route_send_simple(UResp* resp, int status, const char* body, const char* ctype) {
    resp->status = status;
    uresp_header(resp, "Content-Type", ctype ? ctype : "text/plain; charset=utf-8");
    ubuf_adds(&resp->body, body);
}

static void redirect(UResp* resp, const char* loc) {
    resp->status = 302;
    uresp_header(resp, "Location", loc);
    resp->has_ctype = 1; resp->close = 1;
}

/* WebServer::isBlocked: server-internal directories and any dot-segment
   except /.well-known/ (which also makes every "/.." a 403). */
static int is_blocked(const char* p) {
    static const char* pre[] = { "/config/", "/classes/", "/handlers/", "/scripts/", NULL };
    for (int i = 0; pre[i]; i++) if (!strncmp(p, pre[i], strlen(pre[i]))) return 1;
    for (const char* s = strstr(p, "/."); s; s = strstr(s + 1, "/."))
        if (strncmp(s, "/.well-known", 12) != 0) return 1;
    return 0;
}

static int file_exists(const char* p, struct stat* st) { return stat(p, st) == 0; }

static int serve_asset(UReq* req, UResp* resp, const char* rel, const char* ctype) {
    if (!g_cfg.assets) return 0;
    char p[PATH_MAX]; snprintf(p, sizeof p, "%s/%s", g_cfg.assets, rel);
    FILE* f = fopen(p, "rb");
    if (!f) { route_send_simple(resp, 404, "Not found", NULL); return 1; }
    char b[65536]; size_t n; while ((n = fread(b, 1, sizeof b, f)) > 0) ubuf_add(&resp->body, b, n); fclose(f);
    resp->status = 200;
    uresp_header(resp, "Content-Type", ctype);
    uresp_header(resp, "Cache-Control", "public, max-age=86400");
    resp->head_only = !strcmp(req->method, "HEAD");
    return 1;
}

static void dir_listing(UReq* req, UResp* resp, const char* dir) {
    UBuf* o = &resp->body;
    ubuf_adds(o, "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Index of ");
    html_escape(o, req->path);
    ubuf_adds(o, "</title><style>body{font-family:-apple-system,sans-serif;margin:24px}a{text-decoration:none}li{margin:4px 0}</style></head><body><h1>Index of ");
    html_escape(o, req->path); ubuf_adds(o, "</h1><ul>");
    DIR* d = opendir(dir);
    if (d) {
        struct dirent* e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;   /* dotfiles are never listed */
            ubuf_adds(o, "<li><a href=\""); html_escape(o, e->d_name);
            if (e->d_type == DT_DIR) ubuf_adds(o, "/");
            ubuf_adds(o, "\">"); html_escape(o, e->d_name); if (e->d_type == DT_DIR) ubuf_adds(o, "/");
            ubuf_adds(o, "</a></li>");
        }
        closedir(d);
    }
    ubuf_adds(o, "</ul></body></html>");
    resp->status = 200;
    uresp_header(resp, "Content-Type", "text/html; charset=utf-8");
    uresp_header(resp, "Cache-Control", "no-store");
    metrics_inject(o, "text/html", req);
}

static const char* root_for(const UReq* req) {
    const char* host = ureq_header(req, "host");
    if (!host || !g_cfg.vhosts) return g_cfg.root;
    char h[256]; snprintf(h, sizeof h, "%s", host);
    char* c = strrchr(h, ':'); if (c && !strchr(h, ']')) *c = 0;
    for (char* p = h; *p; p++) *p = (char)tolower((unsigned char)*p);
    for (UVhost* v = g_cfg.vhosts; v; v = v->next) if (!strcmp(v->host, h)) return v->root;
    return g_cfg.root;
}

/* resolveStatic: realpath of root + path; NULL when it does not exist or the
   decoded path held a NUL byte. */
static char* resolve(const char* root, const UReq* req) {
    if (req->path_nul) return NULL;
    char cand[PATH_MAX];
    snprintf(cand, sizeof cand, "%s%s", root, req->path[0] == '/' ? req->path + 1 : req->path);
    return realpath(cand, NULL);
}

static int ends_with(const char* s, const char* suf) { size_t a = strlen(s), b = strlen(suf); return a >= b && !strcmp(s + a - b, suf); }

/* Paths outside /Q/ that Qbix answers from its control code rather than
   the document root. An OpenClaiming claim falls through to the docroot in
   Qbix when no claim exists; here a docroot file of that name wins first,
   and control.php answers 404 when neither exists. */
static int control_path(const UReq* req, const char* root) {
    const char* p = req->path; const char* m = req->method;
    if (!strcmp(p, "/llms.txt") || !strcmp(p, "/.well-known/llm.txt") || !strcmp(p, "/mcp")) return 1;
    if (!strcmp(p, "/Q/event")) return !strcmp(m, "POST");
    if (!strncmp(p, "/api/branch/download/", 21)) return !strcmp(m, "GET") || !strcmp(m, "POST");
    if (!strncmp(p, "/api/branch/", 12)) return !strcmp(m, "POST");
    if (strncmp(p, "/.well-known/", 13)) return 0;
    const char* w = p + 13;
    static const char* names[] = { "qbix", "qbix.json", "openapi", "openapi.json", "mcp", "mcp.json",
                                   "ai-plugin.json", "openai-apps-challenge", NULL };
    for (int i = 0; names[i]; i++) if (!strcmp(w, names[i])) return 1;
    if (!strncmp(w, "openclaiming/", 13) && w[13]) {
        char fp[PATH_MAX]; struct stat st;
        snprintf(fp, sizeof fp, "%s%s", root, p + 1);
        return !(stat(fp, &st) == 0 && S_ISREG(st.st_mode));
    }
    return 0;
}

/* Can this server handle PHP at all?  True when the in-process PHP plane is
   running, or when process-mode workers are alive (they embed PHP). */
static int can_php(void) { return php_enabled() || proc_enabled(); }

/* Dispatch a PHP request.  When process mode is active and we are in the
   parent (c != NULL), use the worker processes; otherwise fall through to
   the in-process PHP thread pool. */
static int dispatch_php(UConn* c, UReq* req, const char* script, const char* path_info, double t0) {
    if (c && proc_enabled())
        return proc_dispatch(c, req, t0) == 0;   /* 1 on success (handed off) */
    return php_dispatch(c, req, script, path_info, t0);
}

int route_request(UConn* c, UReq* req, UResp* resp) {
    const char* path = req->path;
    int head = !strcmp(req->method, "HEAD");
    int getlike = head || !strcmp(req->method, "GET");
    double t0 = now_s();

    if (strstr(req->query, "Q.clearCache")) {
        static_cache_clear();
        route_send_simple(resp, 200, "{\"cleared\":[\"fileCache\"]}", "application/json");
        return 1;
    }
    /* ACME HTTP-01: tokens the provisioning thread put in the shared store */
    if (!strncmp(path, "/.well-known/acme-challenge/", 28) && path[28]) {
        char key[512]; snprintf(key, sizeof key, "acme-challenge/%s", path + 28);
        UBuf b = {0};
        if (php_shared_lookup(key, &b)) {
            resp->status = 200; uresp_header(resp, "Content-Type", "text/plain");
            ubuf_add(&resp->body, b.data ? b.data : "", b.len); ubuf_free(&b);
            return 1;
        }
    }
    /* ── proxy backends (optional, off by default) ──────────────── */
    UBackend* be = proxy_match(req);
    if (be) return proxy_dispatch(c, req, resp, be, t0);

    const char* root = root_for(req);

    /* built-in assets */
    if (!strcmp(path, "/Q/socket.js")) return serve_asset(req, resp, "socket.js", "application/javascript");
    if (!strcmp(path, "/socket.io/socket.io.js")) return serve_asset(req, resp, "socket.io.js", "application/javascript");
    if (!strcmp(path, "/Q/logo.svg")) return serve_asset(req, resp, "logo.svg", "image/svg+xml");
    if (!strcmp(path, "/Q/logo.png")) return serve_asset(req, resp, "logo.png", "image/png");
    if (!strcmp(path, "/Q/prism.js")) return serve_asset(req, resp, "prism.js", "application/javascript");
    if (!strcmp(path, "/Q/prism.css")) return serve_asset(req, resp, "prism.css", "text/css");
    if (!strcmp(path, "/favicon.ico")) {
        char fp[PATH_MAX]; struct stat st; snprintf(fp, sizeof fp, "%sfavicon.ico", root);
        if (!file_exists(fp, &st)) return serve_asset(req, resp, "logo.png", "image/png");
    }
    if (!strncmp(path, "/Q/plugins/", 11) && !strstr(path, "..")) {
        char rel[PATH_MAX]; snprintf(rel, sizeof rel, "plugins/%s", path + 11);
        const char* dot = strrchr(path, '.');
        const char* ct = "application/octet-stream";
        if (dot) {
            if (!strcmp(dot, ".js")) ct = "application/javascript"; else if (!strcmp(dot, ".json")) ct = "application/json";
            else if (!strcmp(dot, ".css")) ct = "text/css"; else if (!strcmp(dot, ".html")) ct = "text/html";
            else if (!strcmp(dot, ".png")) ct = "image/png"; else if (!strcmp(dot, ".jpg")) ct = "image/jpeg";
            else if (!strcmp(dot, ".svg")) ct = "image/svg+xml"; else if (!strcmp(dot, ".woff2")) ct = "font/woff2";
        }
        char fp[PATH_MAX]; struct stat st; snprintf(fp, sizeof fp, "%s/%s", g_cfg.assets ? g_cfg.assets : "", rel);
        if (g_cfg.assets && file_exists(fp, &st) && S_ISREG(st.st_mode)) return serve_asset(req, resp, rel, ct);
    }

    /* Qbix's discovery and control endpoints outside /Q/ (WebServer.php
       handles these after the assets and before the /Q/ block) */
    const char* cs = php_control_script();
    if (cs && control_path(req, root)) return dispatch_php(c, req, cs, NULL, t0) ? 0 : (route_error_page(resp, 503, path), 1);

    /* /Q/ control endpoints */
    if (!strncmp(path, "/Q/", 3)) {
        if (!strcmp(path, "/Q/health")) {
            UBuf b = {0}; stats_health(&b);
            resp->status = 200; uresp_header(resp, "Content-Type", "application/json");
            ubuf_add(&resp->body, b.data, b.len); ubuf_free(&b);
            return 1;
        }
        if (!strcmp(path, "/Q/metrics")) {
            UBuf b = {0}; stats_prometheus(&b);
            resp->status = 200; uresp_header(resp, "Content-Type", "text/plain; version=0.0.4");
            ubuf_add(&resp->body, b.data, b.len); ubuf_free(&b);
            return 1;
        }
        if (!strncmp(path, "/Q/clientMetrics/Metrics", 24) && ends_with(path, ".js") && !strchr(path + 17, '/')) {
            char rel[PATH_MAX]; snprintf(rel, sizeof rel, "WebServer/ClientMetrics/%s", path + 17);
            return serve_asset(req, resp, rel, "application/javascript; charset=utf-8");
        }
        if (!strcmp(path, "/Q/clientMetrics") && !strcmp(req->method, "POST")) {
            route_send_simple(resp, 204, "", "text/plain; charset=utf-8");
            return 1;
        }
        if (cs) {
            /* the rest of /Q/ is Qbix's own control plane (panel, dashboard,
               /Q/stats, docs, sync, cluster ...), run by php/control.php.
               /Q/ws too: Qbix's code checks the token, and its upgrade call
               comes back as resp.upgrade for the native side to perform. */
            return dispatch_php(c, req, cs, NULL, t0) ? 0 : (route_error_page(resp, 503, path), 1);
        }
        if (!strcmp(path, "/Q/panel") || !strncmp(path, "/Q/panel/", 9)) {
            route_send_simple(resp, 403, "Forbidden: the control panel is not enabled on this server", NULL);
            return 1;
        }
        redirect(resp, "/Q/panel");
        return 1;
    }

    /* WebSocket upgrade on any other path (before the blocked-path check,
       as in Qbix); events go to PHP handlers through ws.c */
    const char* up = ureq_header(req, "upgrade");
    if (up && !strcasecmp(up, "websocket")) {
        if (req->h2_stream) { route_send_simple(resp, 400, "WebSocket needs HTTP/1.1", NULL); return 1; }
        if (ws_upgrade(c, req, NULL, 1)) return 2;
        route_send_simple(resp, 400, "Bad WebSocket handshake", NULL);
        resp->close = 1;
        return 1;
    }

    if (is_blocked(path)) { route_error_page(resp, 403, path); return 1; }

    /* ZIP overlay: check appended archive BEFORE filesystem (ZIP shadows disk) */
    if (zipfs_active()) {
        const char* zpath = path;
        while (*zpath == '/') zpath++;
        /* bare "/" → try index.html in ZIP */
        const char* zcheck = (zpath[0] == '\0') ? "index.html" : zpath;
        const ZipEntry* ze = zipfs_lookup(zcheck);
        if (ze) {
            const char* ext = strrchr(zcheck, '.');
            if (ext && strcasecmp(ext, ".php") == 0) {
                if (!can_php()) { route_error_page(resp, 503, path); return 1; }
                char* extracted = zipfs_extract_php(ze);
                if (extracted) {
                    int r = dispatch_php(c, req, extracted, NULL, t0);
                    free(extracted);
                    if (!r) { route_error_page(resp, 503, path); return 1; }
                    return 0;
                }
                route_error_page(resp, 500, path);
                return 1;
            }
            if (getlike && zipfs_serve_static(ze, req, resp)) return 1;
        }
    }

    char* fs = resolve(root, req);
    struct stat st;
    if (fs && stat(fs, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (!ends_with(path, "/")) {
            UBuf loc = {0}; ubuf_adds(&loc, path); ubuf_add(&loc, "/", 1);
            redirect(resp, loc.data); ubuf_free(&loc); free(fs);
            return 1;
        }
        const char* idx[] = { "index.html", "index.php", NULL };
        for (int i = 0; idx[i]; i++) {
            char ip[PATH_MAX]; struct stat is; snprintf(ip, sizeof ip, "%s/%s", fs, idx[i]);
            if (stat(ip, &is) == 0 && S_ISREG(is.st_mode)) { free(fs); fs = strdup(ip); st = is; break; }
        }
        if (S_ISDIR(st.st_mode)) {
            int indexed = g_cfg.indexed && !strncmp(path, g_cfg.indexed, strlen(g_cfg.indexed));
            if (indexed || !strcmp(path, "/")) dir_listing(req, resp, fs);
            else route_error_page(resp, 403, path);
            free(fs);
            return 1;
        }
    }

    /* script.php/path/info */
    if (!fs || !S_ISREG(st.st_mode)) {
        char prefix[PATH_MAX] = "";
        const char* seg = path;
        while (*seg == '/') seg++;
        while (*seg) {
            const char* e = strchr(seg, '/');
            size_t l = e ? (size_t)(e - seg) : strlen(seg);
            strncat(prefix, "/", sizeof prefix - strlen(prefix) - 1);
            strncat(prefix, seg, l < sizeof prefix - strlen(prefix) - 1 ? l : sizeof prefix - strlen(prefix) - 1);
            if (ends_with(prefix, ".php")) {
                char cand[PATH_MAX]; struct stat cs; snprintf(cand, sizeof cand, "%s%s", root, prefix + 1);
                if (stat(cand, &cs) == 0 && S_ISREG(cs.st_mode)) {
                    free(fs);
                    if (!can_php()) { route_error_page(resp, 503, path); return 1; }
                    return dispatch_php(c, req, cand, e ? e : "", t0) ? 0 : (route_error_page(resp, 503, path), 1);
                }
            }
            if (!e) break;
            seg = e + 1;
        }
    }

    if (fs && S_ISREG(st.st_mode)) {
        if (ends_with(fs, ".php")) {
            /* never as text: without a PHP plane the answer is 503 */
            if (!can_php()) { free(fs); route_error_page(resp, 503, path); return 1; }
            int r = dispatch_php(c, req, fs, NULL, t0);
            free(fs);
            if (!r) { route_error_page(resp, 503, path); return 1; }
            return 0;
        }
        if (getlike) {
            static_serve(req, resp, fs, head);
            free(fs);
            return 1;
        }
    }
    free(fs);

    /* clean URL -> index.php */
    char ip[PATH_MAX]; snprintf(ip, sizeof ip, "%sindex.php", root);
    if (file_exists(ip, &st) && S_ISREG(st.st_mode)) {
        if (!can_php()) { route_error_page(resp, 503, path); return 1; }
        return dispatch_php(c, req, ip, NULL, t0) ? 0 : (route_error_page(resp, 503, path), 1);
    }
    if (g_cfg.fallback) {
        char fp[PATH_MAX]; snprintf(fp, sizeof fp, "%s%s", root, g_cfg.fallback);
        if (file_exists(fp, &st) && S_ISREG(st.st_mode)) { static_serve(req, resp, fp, head); return 1; }
    }

    /* (ZIP overlay is checked above, before filesystem resolve) */

    route_error_page(resp, 404, path);
    return 1;
}
