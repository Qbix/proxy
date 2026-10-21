/*
 * userver.h — shared types for the U webserver.
 *
 * Layout of the server (see webserver-plan.md, "Architecture"):
 *   loop.c     N event-loop threads, each with its own epoll and its own
 *              SO_REUSEPORT listening socket; connections stay on the
 *              thread that accepted them
 *   http.c     incremental HTTP/1.1 request parsing, with Qbix Server's
 *              validation rules (malformed lines, method case, header
 *              tokens, duplicate Host, 431, 413)
 *   route.c    the request pipeline, in Qbix Server's order
 *   static.c   static files: response cache, ETag/304, gzip and
 *              precompressed siblings, ranges, sendfile, client-metrics
 *              injection, .headers companions
 *   php.c      the PHP plane: real PHP on a thread pool through a SAPI
 *   stats.c    counters shared by every thread, /Q/health, /Q/metrics
 *   config.c   CLI flags and Qbix-style JSON config
 *   json.c     a small JSON reader for config files
 *
 * Everything is C11 + POSIX; the event loop is the only Linux-specific
 * part (epoll), and it sits behind loop.c's interface.
 */
#ifndef USERVER_H
#define USERVER_H

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <strings.h>
#include <unistd.h>

#define USERVER_VERSION "0.2.0"
#define SERVER_TAG      "QbixServer-U/" USERVER_VERSION

/* ── growable byte buffer ─────────────────────────────────────────── */
typedef struct {
    char*  data;
    size_t len, cap;
} UBuf;

void ubuf_reserve(UBuf* b, size_t extra);
void ubuf_add(UBuf* b, const void* p, size_t n);
void ubuf_adds(UBuf* b, const char* s);
void ubuf_printf(UBuf* b, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
void ubuf_free(UBuf* b);
void ubuf_consume(UBuf* b, size_t n);

/* ── a parsed request ─────────────────────────────────────────────── */
#define UREQ_MAX_HEADERS 128

typedef struct { char* name; char* value; } UHeader;   /* name lower-cased */

typedef struct {
    char*    method;
    char*    uri;          /* raw request-target */
    char*    path;         /* decoded, // collapsed */
    char*    query;        /* raw, after '?' */
    char     version[4];   /* "1.1" / "1.0" */
    UHeader  h[UREQ_MAX_HEADERS];
    int      nh;
    UHeader  raw[UREQ_MAX_HEADERS];   /* original-case names, for getallheaders() */
    int      nraw;
    char*    body;
    size_t   body_len;
    int      keep_alive;
    char     remote_ip[64];
    int      remote_port;
    int      local_port;
    int      tls;
    int      path_nul;     /* the path decoded to contain a NUL byte */
    int32_t  h2_stream;    /* HTTP/2 stream id; 0 for HTTP/1.x */
    _Atomic int gone;      /* the client went away while this waited for a PHP thread */
    /* storage the pointers above point into */
    char*    mem;
    char*    bodymem;
    char**   allocs;      /* combined header values, raw names */
    int      nallocs;
} UReq;

const char* ureq_header(const UReq* r, const char* lname);

/* ── response under construction ──────────────────────────────────── */
typedef struct {
    int      status;
    UBuf     head;         /* "Name: value\r\n" lines, without status line */
    UBuf     body;
    int      file_fd;      /* >= 0: send this file after headers */
    off_t    file_off;
    size_t   file_len;
    int      close;        /* close the connection after sending */
    int      head_only;    /* HEAD: send headers only */
    int      has_ctype;
    int      from_php;     /* counted as a PHP request */
    char*    upgrade;      /* PHP (control.php) accepted a WebSocket upgrade: the channel to join */
    int32_t  stream;       /* HTTP/2 stream this (PHP) response belongs to */
} UResp;

void uresp_init(UResp* r);
void uresp_header(UResp* r, const char* name, const char* value);
void uresp_free(UResp* r);

/* ── connection ───────────────────────────────────────────────────── */
struct ULoop;

typedef enum { CONN_READING, CONN_BUSY, CONN_CLOSING } UConnState;

typedef struct UOut {        /* one queued output segment */
    struct UOut* next;
    char*  data; size_t len, off;
    int    fd;  off_t foff; size_t flen;   /* file segment when fd >= 0 */
} UOut;

typedef struct UConn {
    int           fd;
    struct ULoop* loop;
    UConnState    state;
    UBuf          in;
    UOut*         out_head;
    UOut*         out_tail;
    int           requests;     /* served on this connection */
    double        last_active;
    int           close_after;  /* close once output drains */
    char          ip[64];
    int           port;
    int           local_port;
    int           want_write;
    uint64_t      id;
    void*         ws;           /* WebSocket state after an upgrade */
    void*         ssl;          /* TLS session (tls.c) */
    int           tls_hs;       /* TLS handshake still in progress */
    void*         h2;           /* HTTP/2 session (h2.c) */
    int           jobs;         /* HTTP/2 streams in the PHP plane */
    UReq*         busy_req;     /* HTTP/1.x: the request the PHP plane holds */
    int           stream_keep;  /* streamed (chunked) PHP response: keep-alive after it */
    int           stream_status;
    struct UConn* next_live;    /* per-loop list, for idle sweeps */
    struct UConn* prev_live;
} UConn;

typedef struct UJson UJson;

/* ── proxy backend (optional, off by default) ────────────────────── */

#define PROXY_MAX_BACKENDS    16
#define PROXY_MAX_ROUTES      32
#define PROXY_MAX_CTYPES      16
#define PROXY_MAX_METHODS      8
#define PROXY_MAX_EXTENSIONS  32
#define PROXY_MAX_MIMETYPES   32

typedef enum { PROTO_FASTCGI, PROTO_HTTP } UProxyProto;

typedef struct {
    int      max_files;                             /* 0 = no uploads allowed */
    size_t   max_file_bytes;                        /* per file */
    char*    allowed_extensions[PROXY_MAX_EXTENSIONS];
    int      n_extensions;
    char*    allowed_mime_types[PROXY_MAX_MIMETYPES]; /* may contain globs e.g. image/star */
    int      n_mime_types;
} UUploadConstraints;

typedef struct {
    size_t   max_body_bytes;                        /* 0 = use global max_post */
    char*    allowed_content_types[PROXY_MAX_CTYPES]; /* base type, no params */
    int      n_content_types;
    char*    allowed_methods[PROXY_MAX_METHODS];
    int      n_methods;
    size_t   max_header_size_bytes;                 /* 0 = use global max_header */
    int      max_headers;                           /* 0 = use UREQ_MAX_HEADERS */
    size_t   max_url_bytes;                         /* 0 = no limit beyond max_header */
    int      max_query_params;                      /* 0 = no limit */
    int      json_max_depth;                        /* 0 = default 32 */
    size_t   json_max_string;                       /* 0 = default 1 MiB */
    size_t   urlenc_max_value;                      /* 0 = default 64 KiB */
    UUploadConstraints upload;
} UBackendConstraints;

typedef struct {
    char*               name;                       /* "php", "node", ... */
    char*               socket_path;                /* Unix socket */
    UProxyProto         protocol;                   /* fastcgi or http */
    char*               routes[PROXY_MAX_ROUTES];   /* prefix matches */
    int                 n_routes;
    UBackendConstraints constraints;
    char*               document_root;              /* DOCUMENT_ROOT for FastCGI, NULL = use g_cfg.root */
} UBackend;

/* ── proxy stats (per-backend counters) ──────────────────────────── */
typedef struct {
    _Atomic uint64_t forwarded;
    _Atomic uint64_t rejected;
    _Atomic uint64_t errors;
    _Atomic uint64_t us_total;      /* forwarding latency, microseconds */
} UProxyStats;

extern UProxyStats g_proxy_stats[PROXY_MAX_BACKENDS];

/* ── configuration ────────────────────────────────────────────────── */
typedef struct UVhost { char* host; char* root; struct UVhost* next; } UVhost;

typedef struct {
    char*    root;            /* document root, with trailing / */
    char*    host;
    int      port;
    int      threads;         /* event loops */
    int      php_threads;     /* PHP plane workers; 0 = no PHP */
    size_t   max_post;        /* 8 MiB, Qbix's default */
    size_t   max_header;      /* 64 KiB */
    int      keepalive_max;   /* 100 */
    double   keepalive_timeout;   /* 15 s */
    size_t   file_cache_max;      /* 64 MiB */
    size_t   file_cache_max_file; /* 1 MiB */
    double   file_cache_check;    /* 1 s */
    int      client_metrics_disabled;
    int      no_json_post;    /* --no-json-post: leave $_POST empty for JSON bodies, as stock PHP does */   /* falsy default: injection on, as in Qbix */
    char*    assets;          /* Qbix's bundled assets (socket.js, logos, Metrics*.js) */
    char*    access_log;
    char*    fallback;        /* Q.webserver.fallback as a file */
    UVhost*  vhosts;
    char*    php_ini;         /* extra INI entries, "k=v\n" */
    char*    php_prepend;     /* auto_prepend_file for Qbix compatibility */
    int      php_max_seconds; /* max_execution_time, 30 */
    char*    worker_script;   /* --worker=FILE: the long-lived worker script */
    char*    worker_front;    /* --worker-front=FILE: requests resolving to FILE go to the workers (default: FILE above) */
    int      worker_threads;  /* --worker-threads=N */
    int      worker_keep_statics; /* falsy default: user-class statics are reset after every request */
    int      test_config;     /* -t */
    char*    config_file;
    char*    indexed;         /* Q.web.indexed.paths prefix, "/img/" */
    int      https_port;      /* --https-port / Q.web.https.port; 0 = from config, -1 = off */
    char*    tls_cert;        /* --cert / Q.web.https.cert */
    char*    tls_key;         /* --key / Q.web.https.key */
    int      no_http2;        /* --no-http2: offer only http/1.1 over TLS, refuse h2c */
    int      process_mode;    /* --process-mode: PHP in spawned worker processes, not threads */
    int      process_workers; /* --process-workers=N (default: cpu count) */
    int      process_worker_fd; /* --process-worker=FD: this *is* a worker child (internal) */
    int      relay_worker_fd;  /* --relay-worker=FD: this *is* the relay child (internal) */
    char*    pack_dir;        /* --pack=DIR: bundle app files into binary, then exit */
    char*    pack_output;     /* --output=FILE: output path for --pack (default ./myapp) */

    /* ── app mode (--app) ─────────────────────────────────────────── */
    int      app_mode;        /* --app: bind localhost, open browser, idle shutdown */
    int      app_port;        /* --app-port=N: fixed port (0 = find a random free port) */
    double   app_idle_timeout;/* seconds of zero connections before shutdown (default 5) */
    int      app_no_open;     /* --app-no-open: skip opening the browser on launch */

    /* ── window management ────────────────────────────────────────── */
    int      app_width;       /* initial browser window width  (0 = OS default) */
    int      app_height;      /* initial browser window height (0 = OS default) */
    int      app_x;           /* initial window x position (-1 = OS default) */
    int      app_y;           /* initial window y position (-1 = OS default) */

    /* ── proxy mode (off by default) ─────────────────────────────── */
    UBackend backends[PROXY_MAX_BACKENDS];
    int      n_backends;                  /* 0 = proxy mode off */
    int      proxy_strip_server;          /* strip Server header from backend responses */
    int      proxy_add_security_headers;  /* add X-Content-Type-Options, X-Frame-Options, etc. */
} UConfig;

extern UConfig g_cfg;
int  config_load(int argc, char** argv);
void load_app_json(void);   /* load app.json from appended ZIP (call after zipfs_init) */
/* the project directory (the document root's parent), and each Qbix JSON
   config in force (<project>/config/server.json, then --config) */
const char* config_project_dir(void);
void config_foreach(void (*fn)(UJson* root, void* arg), void* arg);

/* ── stats ────────────────────────────────────────────────────────── */
typedef struct {
    _Atomic uint64_t requests, php, statics, bytes_out;
    _Atomic uint64_t s2xx, s3xx, s4xx, s5xx;
    _Atomic uint64_t cache_hits, cache_misses;
    _Atomic uint64_t conns_open, conns_total;
    _Atomic uint64_t us_total;      /* summed request time, microseconds */
    _Atomic uint64_t php_busy;
    double started;
} UStats;
extern UStats g_stats;
void   stats_record(int status, uint64_t bytes, double ms, int php, const char* method, const char* uri);

/* what the Qbix dashboard shows, kept natively for every thread (see stats.c) */
typedef struct { char key[160]; uint64_t count; double ms; } UPathStat;
typedef struct { char time[16]; char method[12]; char uri[160]; int status; double ms; } URecent;
int    stats_snapshot(UPathStat* top, int ntop, URecent* recent, int nrecent, uint64_t* codes, int* rps60);
double stats_slowest(char* uri, size_t n);
void   stats_health(UBuf* out);
void   stats_prometheus(UBuf* out);
double now_s(void);

/* ── pieces ───────────────────────────────────────────────────────── */
int  http_parse(UConn* c, UReq* req, UResp* err);   /* 1 complete, 0 need more, -1 error in err */
void ureq_free(UReq* r);
const char* http_reason(int status);

/* route a request; returns 1 if the response is ready in resp, 0 if it was
   handed off (PHP) and will be completed asynchronously, 2 if the
   connection was upgraded to a WebSocket (no HTTP response follows) */
int  route_request(UConn* c, UReq* req, UResp* resp);
void route_error_page(UResp* resp, int code, const char* path);
void route_send_simple(UResp* resp, int status, const char* body, const char* ctype);

int  static_serve(UReq* req, UResp* resp, const char* fs_path, int head);
void static_cache_clear(void);
const char* static_mime(const char* ext);
int  static_ext_allowed(const char* ext);
void metrics_inject(UBuf* body, const char* ctype, const UReq* req);

/* finish a response on its connection (any thread) */
void conn_send_response(UConn* c, UReq* req, UResp* resp, double t0);
void loop_complete(UConn* c, UReq* req, UResp* resp, double t0);   /* from a PHP thread */

/* PHP plane */
int  php_start(void);
void php_stop(void);
int  php_enabled(void);
const char* php_control_script(void);   /* NULL unless PHP and the Qbix sources are present */
int  php_dispatch(UConn* c, UReq* req, const char* script, const char* path_info, double t0);

/* WebSocket and Socket.IO (ws.c) */
void ws_init(void);
int  ws_upgrade(UConn* c, UReq* req, const char* channel, int dispatch);   /* owner loop; 0 = no key */
void ws_on_data(UConn* c);
void ws_conn_closed(UConn* c);
int  ws_post_valid(UConn* c, uint64_t id);
void ws_tick(UConn* c, double now);
void ws_dashboard_request(const char* method, const char* uri, int status, double ms);
int  ws_command(const char* json, size_t n);
void ws_stats_json(UBuf* out);
/* TLS (tls.c) */
int     tls_init(void);                 /* HTTPS port, or 0 when HTTPS is off */
void*   tls_new(int fd);
void    tls_free(void* ssl);
int     tls_handshake(void* ssl, int* want_write);
int     tls_is_h2(void* ssl);
ssize_t tls_read(void* ssl, void* buf, size_t n, int* want_write);
ssize_t tls_write(void* ssl, const void* buf, size_t n, int* want_read);
/* HTTP/2 (h2.c) */
int  h2_start(UConn* c);
void h2_on_data(UConn* c);
void h2_pump(UConn* c);
void h2_complete(UConn* c, UReq* req, UResp* r, double t0);
int  h2_busy(UConn* c);
void h2_mark_gone(UConn* c);
void h2_release(UConn* c, int32_t id);
void h2_free(UConn* c);
/* loop.c services for ws.c */
void conn_write(UConn* c, const void* d, size_t n);
void conn_close_now(UConn* c);
void loop_ws_post(UConn* c, uint64_t sock_id, char* data, size_t n, int close);   /* takes data */
/* php.c services for ws.c */
const char* php_ws_script(const char* name);
int  php_ws_thread_start(const char* script, int fd, const char* info_json, const char* uri);
int  php_shared_lookup(const char* key, UBuf* out);   /* u_shared_set() values */
void tls_acme_start(void);   /* certificates for Q.webserver.domains.*.tls = "auto" */

/* process mode (process.c) */
int  proc_start(int nworkers);
void proc_stop(void);
int  proc_enabled(void);
int  proc_dispatch(UConn* c, UReq* req, double t0);
int  proc_worker_main(int ctrl_fd);

/* relay process (relay.c) */
int  relay_start(void);
void relay_stop(void);
int  relay_enabled(void);
int  relay_dispatch(const char* json_request, char** result);
int  relay_worker_main(int ctrl_fd);

/* ZIP filesystem overlay (zipfs.c) — redbean-style appended archive */
typedef struct ZipEntry ZipEntry;      /* opaque for callers outside zipfs.c */
int             zipfs_init(const char* binary_path);   /* parse appended ZIP; 0 = none found */
int             zipfs_active(void);
const ZipEntry* zipfs_lookup(const char* path);        /* NULL if not in ZIP */
int             zipfs_serve_static(const ZipEntry* e, UReq* req, UResp* resp);
char*           zipfs_extract_php(const ZipEntry* e);  /* caller frees */
void            zipfs_foreach(void (*fn)(const char*, const ZipEntry*, void*), void*);
int             zipfs_count(void);
int             zipfs_pack(const char* dir, const char* output);   /* --pack */
ssize_t         zipfs_read(const ZipEntry* e, uint8_t** out);     /* decompress entry; caller frees *out */
void            zipfs_free(void);

/* proxy (proxy.c) */
UBackend* proxy_match(const UReq* req);   /* NULL if no backend matches */
int  proxy_dispatch(UConn* c, UReq* req, UResp* resp, UBackend* be, double t0);  /* 1=done, 0=async */

/* sanitize (sanitize.c) */
int  sanitize_request(UReq* req, UResp* resp, const UBackendConstraints* bc);  /* 0=ok, -1=rejected (resp filled) */
int  sanitize_content_type(const char* ct, const UBackendConstraints* bc);       /* 0=allowed */
int  sanitize_multipart(UReq* req, UResp* resp, const UBackendConstraints* bc); /* 0=ok, rewrites body */
int  sanitize_json(UReq* req, UResp* resp, const UBackendConstraints* bc);      /* 0=ok */
int  sanitize_urlencoded(UReq* req, UResp* resp, const UBackendConstraints* bc);/* 0=ok */
void sanitize_headers(UReq* req, const char* remote_ip, int tls);               /* strips/adds in place */

/* FastCGI (fastcgi.c) */
int  fastcgi_forward(int sock_fd, UReq* req, UResp* resp,
                     const char* document_root, const char* script_filename);   /* 1=done */

/* access log */
void alog_write(const UReq* req, int status, size_t bytes, double ms);

/* JSON (config) */
UJson*      json_parse(const char* text);
UJson*      json_get(UJson* obj, const char* key);
UJson*      json_path(UJson* root, const char* const* keys);   /* NULL-terminated */
const char* json_str(UJson* v);
double      json_num(UJson* v, double dflt);
int         json_bool(UJson* v, int dflt);
int         json_is_obj(UJson* v);
int         json_obj_size(UJson* v);
const char* json_obj_key(UJson* v, int i);
UJson*      json_obj_val(UJson* v, int i);
void        json_free(UJson* v);
void        json_escape(UBuf* out, const char* s);

#endif
