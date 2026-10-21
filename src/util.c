/* util.c — buffers, responses, a small JSON reader, the access log. */
#include "userver.h"
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>

void ubuf_reserve(UBuf* b, size_t extra) {
    if (b->len + extra + 1 <= b->cap) return;
    size_t nc = b->cap ? b->cap : 256;
    while (nc < b->len + extra + 1) nc *= 2;
    char* nd = realloc(b->data, nc);
    if (!nd) abort();
    b->data = nd; b->cap = nc;
}
void ubuf_add(UBuf* b, const void* p, size_t n) {
    ubuf_reserve(b, n);
    if (n) memcpy(b->data + b->len, p, n);
    b->len += n; b->data[b->len] = 0;
}
void ubuf_adds(UBuf* b, const char* s) { ubuf_add(b, s, strlen(s)); }
void ubuf_printf(UBuf* b, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    va_list ap2; va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n > 0) { ubuf_reserve(b, (size_t)n); vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap2); b->len += (size_t)n; }
    va_end(ap2);
}
void ubuf_free(UBuf* b) { free(b->data); b->data = NULL; b->len = b->cap = 0; }
void ubuf_consume(UBuf* b, size_t n) {
    if (n >= b->len) { b->len = 0; if (b->data) b->data[0] = 0; return; }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n; b->data[b->len] = 0;
}

void uresp_init(UResp* r) { memset(r, 0, sizeof *r); r->status = 200; r->file_fd = -1; }
void uresp_header(UResp* r, const char* name, const char* value) {
    if (strcasecmp(name, "Content-Type") == 0) r->has_ctype = 1;
    ubuf_adds(&r->head, name); ubuf_add(&r->head, ": ", 2); ubuf_adds(&r->head, value); ubuf_add(&r->head, "\r\n", 2);
}
void uresp_free(UResp* r) { ubuf_free(&r->head); ubuf_free(&r->body); if (r->file_fd >= 0) close(r->file_fd); r->file_fd = -1; free(r->upgrade); r->upgrade = NULL; }

double now_s(void) { struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); return ts.tv_sec + ts.tv_nsec / 1e9; }

/* ── JSON ─────────────────────────────────────────────────────────── */
typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } JType;
struct UJson {
    JType   t;
    double  num;
    char*   str;
    int     n;
    char**  keys;
    UJson** vals;
};

static void jskip(const char** p) { while (**p && isspace((unsigned char)**p)) (*p)++; }
static UJson* jval(const char** p, int depth);

static char* jstring(const char** p) {
    if (**p != '"') return NULL;
    (*p)++;
    UBuf b = {0};
    while (**p && **p != '"') {
        if (**p == '\\') {
            (*p)++;
            char c = **p;
            if (c == 'n') ubuf_add(&b, "\n", 1); else if (c == 't') ubuf_add(&b, "\t", 1);
            else if (c == 'r') ubuf_add(&b, "\r", 1); else if (c == 'b') ubuf_add(&b, "\b", 1);
            else if (c == 'f') ubuf_add(&b, "\f", 1);
            else if (c == 'u') {
                unsigned v = 0;
                for (int i = 1; i <= 4; i++) { char h = (*p)[i]; v = v * 16 + (unsigned)(isdigit((unsigned char)h) ? h - '0' : (tolower((unsigned char)h) - 'a' + 10)); }
                *p += 4;
                char u[4]; int k = 0;
                if (v < 0x80) u[k++] = (char)v;
                else if (v < 0x800) { u[k++] = (char)(0xC0 | (v >> 6)); u[k++] = (char)(0x80 | (v & 63)); }
                else { u[k++] = (char)(0xE0 | (v >> 12)); u[k++] = (char)(0x80 | ((v >> 6) & 63)); u[k++] = (char)(0x80 | (v & 63)); }
                ubuf_add(&b, u, (size_t)k);
            } else if (c) ubuf_add(&b, &c, 1);
            if (**p) (*p)++;
        } else { ubuf_add(&b, *p, 1); (*p)++; }
    }
    if (**p == '"') (*p)++;
    if (!b.data) ubuf_add(&b, "", 0);
    return b.data;
}

static UJson* jval(const char** p, int depth) {
    if (depth > 64) return NULL;
    jskip(p);
    UJson* v = calloc(1, sizeof *v);
    if (**p == '{' || **p == '[') {
        int obj = **p == '{';
        v->t = obj ? J_OBJ : J_ARR;
        (*p)++;
        for (;;) {
            jskip(p);
            if (**p == (obj ? '}' : ']')) { (*p)++; break; }
            char* key = NULL;
            if (obj) { key = jstring(p); jskip(p); if (**p == ':') (*p)++; }
            UJson* x = jval(p, depth + 1);
            if (!x) { free(key); json_free(v); return NULL; }
            v->keys = realloc(v->keys, sizeof(char*) * (size_t)(v->n + 1));
            v->vals = realloc(v->vals, sizeof(UJson*) * (size_t)(v->n + 1));
            v->keys[v->n] = key; v->vals[v->n] = x; v->n++;
            jskip(p);
            if (**p == ',') (*p)++;
            else if (**p != (obj ? '}' : ']')) { json_free(v); return NULL; }
        }
    } else if (**p == '"') { v->t = J_STR; v->str = jstring(p); }
    else if (!strncmp(*p, "true", 4)) { v->t = J_BOOL; v->num = 1; *p += 4; }
    else if (!strncmp(*p, "false", 5)) { v->t = J_BOOL; v->num = 0; *p += 5; }
    else if (!strncmp(*p, "null", 4)) { v->t = J_NULL; *p += 4; }
    else { char* e; v->t = J_NUM; v->num = strtod(*p, &e); if (e == *p) { free(v); return NULL; } *p = e; }
    return v;
}

UJson* json_parse(const char* text) { const char* p = text; return jval(&p, 0); }
UJson* json_get(UJson* o, const char* key) {
    if (!o || o->t != J_OBJ) return NULL;
    for (int i = o->n - 1; i >= 0; i--) if (o->keys[i] && !strcmp(o->keys[i], key)) return o->vals[i];
    return NULL;
}
UJson* json_path(UJson* r, const char* const* keys) { for (; r && *keys; keys++) r = json_get(r, *keys); return r; }
const char* json_str(UJson* v) { return v && v->t == J_STR ? v->str : NULL; }
double json_num(UJson* v, double d) { return v && (v->t == J_NUM || v->t == J_BOOL) ? v->num : d; }
int json_bool(UJson* v, int d) { if (!v) return d; if (v->t == J_BOOL || v->t == J_NUM) return v->num != 0; if (v->t == J_NULL) return 0; return d; }
int json_is_obj(UJson* v) { return v && v->t == J_OBJ; }
int json_obj_size(UJson* v) { return v && (v->t == J_OBJ || v->t == J_ARR) ? v->n : 0; }
const char* json_obj_key(UJson* v, int i) { return v && v->t == J_OBJ && i < v->n ? v->keys[i] : NULL; }
UJson* json_obj_val(UJson* v, int i) { return v && i < v->n ? v->vals[i] : NULL; }
void json_free(UJson* v) {
    if (!v) return;
    for (int i = 0; i < v->n; i++) { if (v->keys) free(v->keys[i]); json_free(v->vals[i]); }
    free(v->keys); free(v->vals); free(v->str); free(v);
}
void json_escape(UBuf* out, const char* s) {
    ubuf_add(out, "\"", 1);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { char e[2] = { '\\', (char)c }; ubuf_add(out, e, 2); }
        else if (c == '/') ubuf_add(out, "\\/", 2);   /* as PHP's json_encode does */
        else if (c == '\n') ubuf_add(out, "\\n", 2);
        else if (c == '\r') ubuf_add(out, "\\r", 2);
        else if (c == '\t') ubuf_add(out, "\\t", 2);
        else if (c < 0x20) ubuf_printf(out, "\\u%04x", c);
        else ubuf_add(out, (const char*)&c, 1);
    }
    ubuf_add(out, "\"", 1);
}

/* ── access log, combined format ──────────────────────────────────── */
static FILE* g_alog;
static pthread_mutex_t g_alog_mu = PTHREAD_MUTEX_INITIALIZER;
void alog_write(const UReq* req, int status, size_t bytes, double ms) {
    if (!g_cfg.access_log) return;
    pthread_mutex_lock(&g_alog_mu);
    if (!g_alog) g_alog = fopen(g_cfg.access_log, "a");
    if (g_alog) {
        time_t t = time(NULL); struct tm tm; gmtime_r(&t, &tm);
        char ts[64]; strftime(ts, sizeof ts, "%d/%b/%Y:%H:%M:%S +0000", &tm);
        const char* ref = ureq_header(req, "referer"); const char* ua = ureq_header(req, "user-agent");
        fprintf(g_alog, "%s - - [%s] \"%s %s HTTP/%s\" %d %zu \"%s\" \"%s\" %.1fms\n",
                req->remote_ip, ts, req->method, req->uri, req->version, status, bytes,
                ref ? ref : "-", ua ? ua : "-", ms);
        fflush(g_alog);
    }
    pthread_mutex_unlock(&g_alog_mu);
}
