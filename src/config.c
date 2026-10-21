/* config.c — command line and Qbix-style JSON config.
 *
 * Flags follow qbixserver.php where they overlap, so the parity harness can
 * start either server with the same arguments:
 *   --root=DIR --port=N --host=ADDR --config=FILE.json -t
 *   --workers=N        PHP threads (Qbix: worker processes)
 *   --threads=N        event-loop threads (default: one per core)
 *   --assets=DIR       Qbix's bundled assets (src/Q of a Qbix checkout)
 *   --access-log=FILE  combined log format
 *   --no-client-metrics
 *   --max-post=BYTES   --php-ini=key=value (repeatable)  --php-prepend=FILE
 *   --php-timeout=S    max_execution_time for PHP requests (30)
 * The JSON file is read for the keys Qbix uses under "Q":
 *   webserver.{port,host,root,workers,keepAlive.{max,timeout},
 *   fileCache.{maxSize,maxFile,checkInterval},clientMetrics.enabled,
 *   hosts.<name>.root, domains.<name>.root, fallback}, web.indexed
 */
#include "userver.h"
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

UConfig g_cfg;

static char* slashed(const char* dir) {
    char* r = realpath(dir, NULL);
    if (!r) return NULL;
    size_t l = strlen(r);
    char* o = malloc(l + 2); memcpy(o, r, l); if (l == 0 || o[l - 1] != '/') o[l++] = '/'; o[l] = 0;
    free(r);
    return o;
}

static void add_vhost(const char* host, const char* root) {
    char* r = slashed(root);
    if (!r) { fprintf(stderr, "[config] vhost %s: root %s does not exist\n", host, root); return; }
    UVhost* v = calloc(1, sizeof *v);
    v->host = strdup(host); for (char* p = v->host; *p; p++) *p = (char)tolower((unsigned char)*p);
    v->root = r; v->next = g_cfg.vhosts; g_cfg.vhosts = v;
}

static void load_json(const char* file) {
    FILE* f = fopen(file, "rb");
    if (!f) { fprintf(stderr, "[config] cannot read %s\n", file); exit(1); }
    UBuf b = {0}; char t[8192]; size_t n; while ((n = fread(t, 1, sizeof t, f)) > 0) ubuf_add(&b, t, n); fclose(f);
    UJson* j = json_parse(b.data ? b.data : "{}");
    ubuf_free(&b);
    if (!j) { fprintf(stderr, "[config] %s is not valid JSON\n", file); exit(1); }
    const char* ws[] = { "Q", "webserver", NULL };
    UJson* w = json_path(j, ws);
    if (w) {
        if (json_get(w, "port")) g_cfg.port = (int)json_num(json_get(w, "port"), g_cfg.port);
        if (json_str(json_get(w, "host"))) g_cfg.host = strdup(json_str(json_get(w, "host")));
        if (json_str(json_get(w, "root"))) g_cfg.root = slashed(json_str(json_get(w, "root")));
        if (json_get(w, "workers")) g_cfg.php_threads = (int)json_num(json_get(w, "workers"), g_cfg.php_threads);
        UJson* ka = json_get(w, "keepAlive");
        g_cfg.keepalive_max = (int)json_num(json_get(ka, "max"), g_cfg.keepalive_max);
        g_cfg.keepalive_timeout = json_num(json_get(ka, "timeout"), g_cfg.keepalive_timeout);
        UJson* fc = json_get(w, "fileCache");
        g_cfg.file_cache_max = (size_t)json_num(json_get(fc, "maxSize"), (double)g_cfg.file_cache_max);
        g_cfg.file_cache_max_file = (size_t)json_num(json_get(fc, "maxFile"), (double)g_cfg.file_cache_max_file);
        g_cfg.file_cache_check = json_num(json_get(fc, "checkInterval"), g_cfg.file_cache_check);
        UJson* cm = json_get(w, "clientMetrics");
        if (cm && !json_bool(json_get(cm, "enabled"), 1)) g_cfg.client_metrics_disabled = 1;
        const char* hk[] = { "hosts", "domains" };
        for (int k = 0; k < 2; k++) {
            UJson* hs = json_get(w, hk[k]);
            for (int i = 0; i < json_obj_size(hs); i++) {
                const char* r = json_str(json_get(json_obj_val(hs, i), "root"));
                if (json_obj_key(hs, i) && r) add_vhost(json_obj_key(hs, i), r);
            }
        }
        if (json_str(json_get(w, "fallback"))) g_cfg.fallback = strdup(json_str(json_get(w, "fallback")));
    }

    /* ── proxy backends (optional — off by default) ───────────── */
    UJson* backends = json_get(j, "backends");
    if (!backends) {
        /* Also try under Q.webserver.backends */
        const char* bp[] = { "Q", "webserver", "backends", NULL };
        backends = json_path(j, bp);
    }
    if (backends && json_is_obj(backends)) {
        for (int bi = 0; bi < json_obj_size(backends) && g_cfg.n_backends < PROXY_MAX_BACKENDS; bi++) {
            const char* bname = json_obj_key(backends, bi);
            UJson* bobj = json_obj_val(backends, bi);
            if (!bname || !json_is_obj(bobj)) continue;

            UBackend* be = &g_cfg.backends[g_cfg.n_backends];
            memset(be, 0, sizeof *be);
            be->name = strdup(bname);

            const char* sock = json_str(json_get(bobj, "socket"));
            if (!sock) { fprintf(stderr, "[config] backend %s: missing socket\n", bname); free(be->name); continue; }
            be->socket_path = strdup(sock);

            const char* proto = json_str(json_get(bobj, "protocol"));
            if (proto && !strcasecmp(proto, "http")) be->protocol = PROTO_HTTP;
            else be->protocol = PROTO_FASTCGI;  /* default */

            const char* docroot = json_str(json_get(bobj, "document_root"));
            if (docroot) be->document_root = strdup(docroot);

            /* routes */
            UJson* routes = json_get(bobj, "routes");
            for (int ri = 0; ri < json_obj_size(routes) && be->n_routes < PROXY_MAX_ROUTES; ri++) {
                /* routes is an array — json_obj_val works for arrays too via json_get by index */
                const char* rv = json_str(json_obj_val(routes, ri));
                if (rv) be->routes[be->n_routes++] = strdup(rv);
            }

            /* constraints */
            UJson* con = json_get(bobj, "constraints");
            if (con) {
                UBackendConstraints* bc = &be->constraints;
                bc->max_body_bytes = (size_t)json_num(json_get(con, "max_body_bytes"), 0);
                bc->max_header_size_bytes = (size_t)json_num(json_get(con, "max_header_size_bytes"), 0);
                bc->max_headers = (int)json_num(json_get(con, "max_headers"), 0);
                bc->max_url_bytes = (size_t)json_num(json_get(con, "max_url_bytes"), 0);
                bc->max_query_params = (int)json_num(json_get(con, "max_query_params"), 0);
                bc->json_max_depth = (int)json_num(json_get(con, "json_max_depth"), 0);
                bc->json_max_string = (size_t)json_num(json_get(con, "json_max_string"), 0);
                bc->urlenc_max_value = (size_t)json_num(json_get(con, "urlenc_max_value"), 0);

                /* allowed_content_types */
                UJson* act = json_get(con, "allowed_content_types");
                for (int ci = 0; ci < json_obj_size(act) && bc->n_content_types < PROXY_MAX_CTYPES; ci++) {
                    const char* cv = json_str(json_obj_val(act, ci));
                    if (cv) bc->allowed_content_types[bc->n_content_types++] = strdup(cv);
                }

                /* allowed_methods */
                UJson* am = json_get(con, "allowed_methods");
                for (int mi = 0; mi < json_obj_size(am) && bc->n_methods < PROXY_MAX_METHODS; mi++) {
                    const char* mv = json_str(json_obj_val(am, mi));
                    if (mv) bc->allowed_methods[bc->n_methods++] = strdup(mv);
                }

                /* upload constraints */
                UJson* up = json_get(con, "upload");
                if (up) {
                    UUploadConstraints* uc = &bc->upload;
                    uc->max_files = (int)json_num(json_get(up, "max_files"), 0);
                    uc->max_file_bytes = (size_t)json_num(json_get(up, "max_file_bytes"), 0);

                    UJson* ae = json_get(up, "allowed_extensions");
                    for (int ei = 0; ei < json_obj_size(ae) && uc->n_extensions < PROXY_MAX_EXTENSIONS; ei++) {
                        const char* ev = json_str(json_obj_val(ae, ei));
                        if (ev) uc->allowed_extensions[uc->n_extensions++] = strdup(ev);
                    }

                    UJson* amt = json_get(up, "allowed_mime_types");
                    for (int mi = 0; mi < json_obj_size(amt) && uc->n_mime_types < PROXY_MAX_MIMETYPES; mi++) {
                        const char* mv = json_str(json_obj_val(amt, mi));
                        if (mv) uc->allowed_mime_types[uc->n_mime_types++] = strdup(mv);
                    }
                }
            }

            g_cfg.n_backends++;
            fprintf(stderr, "[config] backend %s: %s via %s (%d routes)\n",
                    bname, be->socket_path,
                    be->protocol == PROTO_HTTP ? "http" : "fastcgi",
                    be->n_routes);
        }
    }

    json_free(j);
}

static char* default_assets(void) {
    const char* env = getenv("QBIX_ASSETS");
    if (env) return strdup(env);
    char exe[PATH_MAX]; ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n <= 0) return NULL;
    exe[n] = 0;
    char* d = strrchr(exe, '/'); if (d) *d = 0;
    const char* tries[] = { "%s/assets", "%s/../../../qbix-webserver/src/Q", NULL };
    for (int i = 0; tries[i]; i++) {
        char p[PATH_MAX], probe[PATH_MAX + 32]; snprintf(p, sizeof p, tries[i], exe);
        snprintf(probe, sizeof probe, "%s/socket.js", p);
        if (access(probe, R_OK) == 0) return realpath(p, NULL);
    }
    return NULL;
}

/* Strip C-style block comments from JSON text in-place.
   Qbix convention: JSON config files may contain block comments. */
static void strip_json_comments(char* s) {
    char* r = s, *w = s;
    while (*r) {
        if (r[0] == '/' && r[1] == '*') {
            r += 2;
            while (*r && !(r[0] == '*' && r[1] == '/')) r++;
            if (*r) r += 2;
        } else if (r[0] == '"') {
            *w++ = *r++;
            while (*r && *r != '"') { if (*r == '\\' && r[1]) { *w++ = *r++; } *w++ = *r++; }
            if (*r) *w++ = *r++;
        } else {
            *w++ = *r++;
        }
    }
    *w = 0;
}

/* Load app.json from an appended ZIP archive, if present.
   Called after zipfs_init() so the overlay is mounted. */
void load_app_json(void) {
    const ZipEntry* e = zipfs_lookup("app.json");
    if (!e) return;
    uint8_t* data = NULL;
    ssize_t len = zipfs_read(e, &data);
    if (len <= 0 || !data) return;

    char* text = malloc((size_t)len + 1);
    memcpy(text, data, (size_t)len);
    text[len] = 0;
    free(data);

    strip_json_comments(text);
    UJson* j = json_parse(text);
    free(text);
    if (!j) { fprintf(stderr, "[config] app.json in ZIP is not valid JSON\n"); return; }

    /* App-level config: port, open, idle, window geometry */
    if (json_get(j, "port"))  g_cfg.app_port = (int)json_num(json_get(j, "port"), 0);
    if (json_get(j, "idle"))  g_cfg.app_idle_timeout = json_num(json_get(j, "idle"), g_cfg.app_idle_timeout);
    if (json_get(j, "noOpen")) g_cfg.app_no_open = json_bool(json_get(j, "noOpen"), 0);

    UJson* win = json_get(j, "window");
    if (win) {
        if (json_get(win, "width"))  g_cfg.app_width  = (int)json_num(json_get(win, "width"), 0);
        if (json_get(win, "height")) g_cfg.app_height = (int)json_num(json_get(win, "height"), 0);
        if (json_get(win, "x"))      g_cfg.app_x      = (int)json_num(json_get(win, "x"), -1);
        if (json_get(win, "y"))      g_cfg.app_y      = (int)json_num(json_get(win, "y"), -1);
    }

    /* Also load webserver settings if present under "Q.webserver" */
    const char* ws[] = { "Q", "webserver", NULL };
    UJson* w = json_path(j, ws);
    if (w) {
        if (json_get(w, "port")) g_cfg.port = (int)json_num(json_get(w, "port"), g_cfg.port);
        if (json_str(json_get(w, "host"))) g_cfg.host = strdup(json_str(json_get(w, "host")));
        if (json_str(json_get(w, "root"))) g_cfg.root = slashed(json_str(json_get(w, "root")));
    }

    json_free(j);
    fprintf(stderr, "[config] loaded app.json from ZIP\n");
}

int config_load(int argc, char** argv) {
    g_cfg.port = 8080;
    g_cfg.host = "0.0.0.0";
    g_cfg.app_x = -1;
    g_cfg.app_y = -1;
    g_cfg.app_idle_timeout = 5.0;
    long nc = sysconf(_SC_NPROCESSORS_ONLN);
    g_cfg.threads = nc > 0 ? (int)nc : 1;
    g_cfg.php_threads = -1;   /* decided below */
    g_cfg.max_post = 8u << 20;
    g_cfg.max_header = 65536;
    g_cfg.keepalive_max = 100;
    g_cfg.keepalive_timeout = 15;
    g_cfg.file_cache_max = 64u << 20;
    g_cfg.file_cache_max_file = 1u << 20;
    g_cfg.file_cache_check = 1;
    g_cfg.indexed = "/img/";
    g_cfg.php_max_seconds = 30;
    UBuf ini = {0};

    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        const char* v = strchr(a, '=');
        v = v ? v + 1 : "";
#define IS(x) (!strncmp(a, x, strlen(x)))
        if (!strcmp(a, "-t")) g_cfg.test_config = 1;
        else if (IS("--root=")) { g_cfg.root = slashed(v); if (!g_cfg.root) { fprintf(stderr, "Config: root %s does not exist\n", v); return -1; } }
        else if (IS("--port=")) g_cfg.port = atoi(v);
        else if (IS("--host=")) g_cfg.host = strdup(v);
        else if (IS("--threads=")) g_cfg.threads = atoi(v);
        else if (IS("--workers=")) g_cfg.php_threads = atoi(v);
        else if (IS("--config=")) { g_cfg.config_file = strdup(v); load_json(v); }
        else if (IS("--assets=")) g_cfg.assets = realpath(v, NULL);
        else if (IS("--access-log=")) g_cfg.access_log = strdup(v);
        else if (!strcmp(a, "--no-client-metrics")) g_cfg.client_metrics_disabled = 1;
        else if (!strcmp(a, "--no-json-post")) g_cfg.no_json_post = 1;
        else if (IS("--max-post=")) g_cfg.max_post = (size_t)strtoull(v, NULL, 10);
        else if (IS("--php-ini=")) { ubuf_adds(&ini, v); ubuf_add(&ini, "\n", 1); }
        else if (IS("--php-prepend=")) g_cfg.php_prepend = realpath(v, NULL);
        else if (IS("--php-timeout=")) g_cfg.php_max_seconds = atoi(v);
        else if (IS("--fallback=")) g_cfg.fallback = strdup(v);
        else if (IS("--worker=")) { g_cfg.worker_script = realpath(v, NULL); if (!g_cfg.worker_script) { fprintf(stderr, "worker script %s not found\n", v); return -1; } }
        else if (IS("--worker-threads=")) g_cfg.worker_threads = atoi(v);
        else if (IS("--worker-front=")) { g_cfg.worker_front = realpath(v, NULL); if (!g_cfg.worker_front) { fprintf(stderr, "front controller %s not found\n", v); return -1; } }
        else if (!strcmp(a, "--worker-keep-statics")) g_cfg.worker_keep_statics = 1;
        else if (IS("--https-port=")) g_cfg.https_port = atoi(v) > 0 ? atoi(v) : -1;
        else if (IS("--cert=")) g_cfg.tls_cert = realpath(v, NULL);
        else if (IS("--key=")) g_cfg.tls_key = realpath(v, NULL);
        else if (!strcmp(a, "--no-http2")) g_cfg.no_http2 = 1;
        else if (!strcmp(a, "--process-mode")) g_cfg.process_mode = 1;
        else if (IS("--process-workers=")) g_cfg.process_workers = atoi(v);
        else if (IS("--process-worker=")) g_cfg.process_worker_fd = atoi(v);
        else if (IS("--relay-worker=")) g_cfg.relay_worker_fd = atoi(v);
        else if (IS("--pack=")) g_cfg.pack_dir = realpath(v, NULL);
        else if (IS("--output=")) g_cfg.pack_output = strdup(v);
        else if (!strcmp(a, "--app")) g_cfg.app_mode = 1;
        else if (IS("--app-port=")) g_cfg.app_port = atoi(v);
        else if (IS("--app-idle=")) g_cfg.app_idle_timeout = atof(v);
        else if (!strcmp(a, "--app-no-open")) g_cfg.app_no_open = 1;
        else if (IS("--app-width=")) g_cfg.app_width = atoi(v);
        else if (IS("--app-height=")) g_cfg.app_height = atoi(v);
        else if (IS("--app-x=")) g_cfg.app_x = atoi(v);
        else if (IS("--app-y=")) g_cfg.app_y = atoi(v);
        else if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
            printf("usage: userver --root=DIR [--port=N] [--host=ADDR] [--workers=N] [--threads=N] [--config=FILE] [-t]\n"
                   "       userver --pack=DIR [--output=FILE]  (bundle app files into binary)\n"
                   "       userver --app [--app-port=N] [--app-no-open]  (run as local app)\n");
            exit(0);
        } else fprintf(stderr, "[config] ignoring unknown option %s\n", a);
#undef IS
    }
    g_cfg.php_ini = ini.data;
    if (!g_cfg.root) {
        g_cfg.root = slashed("web");
        if (!g_cfg.root) g_cfg.root = slashed(".");
    }
    if (!g_cfg.assets) g_cfg.assets = default_assets();
    if (g_cfg.threads < 1) g_cfg.threads = 1;
    if (g_cfg.php_threads < 0) g_cfg.php_threads = (int)(nc > 0 ? nc : 1) * 8;
    if (g_cfg.worker_script && !g_cfg.worker_front) g_cfg.worker_front = g_cfg.worker_script;
    if (g_cfg.worker_script && g_cfg.worker_threads <= 0) g_cfg.worker_threads = (int)(nc > 0 ? nc : 1) * 2;
    /* ── app mode overrides ─────────────────────────────────────────── */
    if (g_cfg.app_mode) {
        g_cfg.host = "127.0.0.1";   /* always localhost */
        if (g_cfg.app_port > 0)
            g_cfg.port = g_cfg.app_port;
        else
            g_cfg.port = 0;         /* resolved after bind in loop.c */
        g_cfg.threads = 1;          /* single thread suffices for local app */
    }

    if (g_cfg.test_config) {
        printf("Root: %s\nPort: %d\nAssets: %s\nApp: %s\nConfig: OK\n",
               g_cfg.root, g_cfg.port, g_cfg.assets ? g_cfg.assets : "(none)",
               g_cfg.app_mode ? "yes" : "no");
        exit(0);
    }
    return 0;
}

const char* config_project_dir(void) {
    static char dir[PATH_MAX];
    if (!dir[0]) {
        snprintf(dir, sizeof dir, "%s", g_cfg.root);
        size_t l = strlen(dir); while (l > 1 && dir[l - 1] == '/') dir[--l] = 0;
        char* sl = strrchr(dir, '/'); if (sl && sl != dir) *sl = 0;
    }
    return dir;
}

void config_foreach(void (*fn)(UJson* root, void* arg), void* arg) {
    char pf[PATH_MAX]; snprintf(pf, sizeof pf, "%s/config/server.json", config_project_dir());
    const char* files[2] = { pf, g_cfg.config_file };
    for (int f = 0; f < 2; f++) {
        if (!files[f]) continue;
        FILE* fp = fopen(files[f], "rb"); if (!fp) continue;
        UBuf b = {0}; char t[8192]; size_t n; while ((n = fread(t, 1, sizeof t, fp)) > 0) ubuf_add(&b, t, n); fclose(fp);
        UJson* j = json_parse(b.data ? b.data : "{}"); ubuf_free(&b);
        if (j) { fn(j, arg); json_free(j); }
    }
}
