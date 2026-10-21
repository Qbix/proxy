/* stats.c — counters shared by every thread; /Q/health and /Q/metrics.
 *
 * Under Qbix these live in the parent process's PHP statics. Here they are
 * atomics in the one process, so every loop thread and PHP thread adds to
 * the same numbers (the "shared state lives on the native side" rule in
 * webserver-plan.md). /Q/health uses Qbix's key names for the fields it
 * has; /Q/metrics is Prometheus text.
 */
#include "userver.h"
#include <sys/resource.h>
#include <time.h>

UStats g_stats;

/* Per-path counts, per-code counts, the last 60 seconds and the last 50
   requests: the shared state Qbix's dashboard keeps in parent-process
   statics. One mutex; it is taken once per request for a few stores. */
#define NPATHS 512
static UPathStat g_paths[NPATHS];
static int g_npaths;
static URecent g_recent[50];
static int g_recent_at;
static uint64_t g_codes[600];
static int g_rps[60]; static long g_rps_sec[60];
static double g_slowest; static char g_slowest_uri[256];
static pthread_mutex_t g_smu = PTHREAD_MUTEX_INITIALIZER;

static void record_detail(int status, double ms, const char* method, const char* uri) {
    if (!method || !uri) return;
    char key[160]; size_t ul = strcspn(uri, "?");
    snprintf(key, sizeof key, "%s %.*s", method, (int)(ul < 140 ? ul : 140), uri);
    time_t now = time(NULL);
    pthread_mutex_lock(&g_smu);
    if (status > 0 && status < 600) g_codes[status]++;
    int i; for (i = 0; i < g_npaths; i++) if (!strcmp(g_paths[i].key, key)) break;
    if (i == g_npaths && g_npaths < NPATHS) { snprintf(g_paths[i].key, sizeof g_paths[i].key, "%s", key); g_npaths++; }
    if (i < g_npaths) { g_paths[i].count++; g_paths[i].ms += ms; }
    int slot = (int)(now % 60);
    if (g_rps_sec[slot] != now) { g_rps_sec[slot] = now; g_rps[slot] = 0; }
    g_rps[slot]++;
    URecent* r = &g_recent[g_recent_at]; g_recent_at = (g_recent_at + 1) % 50;
    struct tm tm; localtime_r(&now, &tm); strftime(r->time, sizeof r->time, "%H:%M:%S", &tm);
    snprintf(r->method, sizeof r->method, "%s", method); snprintf(r->uri, sizeof r->uri, "%s", uri);
    r->status = status; r->ms = ms;
    if (ms > g_slowest) { g_slowest = ms; snprintf(g_slowest_uri, sizeof g_slowest_uri, "%s", uri); }
    pthread_mutex_unlock(&g_smu);
}

static int by_count(const void* a, const void* b) {
    uint64_t x = ((const UPathStat*)a)->count, y = ((const UPathStat*)b)->count;
    return x < y ? 1 : x > y ? -1 : 0;
}

double stats_slowest(char* uri, size_t n) {
    pthread_mutex_lock(&g_smu);
    double ms = g_slowest; snprintf(uri, n, "%s", g_slowest_uri);
    pthread_mutex_unlock(&g_smu);
    return ms;
}

int stats_snapshot(UPathStat* top, int ntop, URecent* recent, int nrecent, uint64_t* codes, int* rps60) {
    pthread_mutex_lock(&g_smu);
    /* top paths by count */
    UPathStat* all = malloc(sizeof *all * (size_t)(g_npaths ? g_npaths : 1));
    memcpy(all, g_paths, sizeof *all * (size_t)g_npaths);
    qsort(all, (size_t)g_npaths, sizeof *all, by_count);
    int n = g_npaths < ntop ? g_npaths : ntop;
    memcpy(top, all, sizeof *all * (size_t)n);
    free(all);
    int nr = 0;
    for (int i = 0; i < 50 && nr < nrecent; i++) {
        URecent* r = &g_recent[(g_recent_at + 49 - i) % 50];
        if (!r->method[0]) break;
        recent[nr++] = *r;
    }
    memcpy(codes, g_codes, sizeof g_codes);
    time_t now = time(NULL);
    for (int i = 0; i < 60; i++) { long sec = (long)now - 59 + i; int slot = (int)(sec % 60); rps60[i] = g_rps_sec[slot] == sec ? g_rps[slot] : 0; }
    pthread_mutex_unlock(&g_smu);
    return n | (nr << 16);
}

extern _Atomic int g_ws_dash_subs;
void stats_record(int status, uint64_t bytes, double ms, int php, const char* method, const char* uri) {
    record_detail(status, ms, method, uri);
    if (g_ws_dash_subs) ws_dashboard_request(method, uri, status, ms);   /* the dashboard's live feed */
    atomic_fetch_add(&g_stats.requests, 1);
    atomic_fetch_add(&g_stats.bytes_out, bytes);
    atomic_fetch_add(&g_stats.us_total, (uint64_t)(ms * 1000));
    /* Qbix's split: a request is PHP if a PHP worker ran it, otherwise
       "static" (files, errors, redirects and its own control plane) */
    if (php) atomic_fetch_add(&g_stats.php, 1);
    else atomic_fetch_add(&g_stats.statics, 1);
    if (status >= 500) atomic_fetch_add(&g_stats.s5xx, 1);
    else if (status >= 400) atomic_fetch_add(&g_stats.s4xx, 1);
    else if (status >= 300) atomic_fetch_add(&g_stats.s3xx, 1);
    else atomic_fetch_add(&g_stats.s2xx, 1);
}

static long rss_kb(void) {
    FILE* f = fopen("/proc/self/statm", "r");
    long pages = 0, res = 0;
    if (f) { if (fscanf(f, "%ld %ld", &pages, &res) != 2) res = 0; fclose(f); }
    return res * (sysconf(_SC_PAGESIZE) / 1024);
}

void stats_health(UBuf* o) {
    double up = now_s() - g_stats.started;
    uint64_t req = atomic_load(&g_stats.requests);
    uint64_t hits = atomic_load(&g_stats.cache_hits), miss = atomic_load(&g_stats.cache_misses);
    ubuf_printf(o, "{\"status\":\"ok\",\"server\":\"%s\",\"uptime\":\"%ds\",\"uptimeSec\":%d,\"requests\":%llu,"
        "\"rps\":%.0f,\"avgMs\":%.2f,\"status2xx\":%llu,\"status3xx\":%llu,\"status4xx\":%llu,\"status5xx\":%llu,"
        "\"phpRequests\":%llu,\"staticRequests\":%llu,\"bytesOut\":%llu,\"memory\":%ld,"
        "\"threads\":%d,\"phpThreads\":%d,\"phpBusy\":%llu,\"connections\":%llu,\"keepAlive\":%llu,"
        "\"cache\":{\"hits\":%llu,\"misses\":%llu,\"hitRate\":%.3f},\"os\":\"Linux\"}",
        SERVER_TAG, (int)up, (int)up, (unsigned long long)req, up > 0 ? req / up : 0,
        req ? atomic_load(&g_stats.us_total) / 1000.0 / req : 0,
        (unsigned long long)atomic_load(&g_stats.s2xx), (unsigned long long)atomic_load(&g_stats.s3xx),
        (unsigned long long)atomic_load(&g_stats.s4xx), (unsigned long long)atomic_load(&g_stats.s5xx),
        (unsigned long long)atomic_load(&g_stats.php), (unsigned long long)atomic_load(&g_stats.statics),
        (unsigned long long)atomic_load(&g_stats.bytes_out), rss_kb() / 1024,
        g_cfg.threads, g_cfg.php_threads, (unsigned long long)atomic_load(&g_stats.php_busy),
        (unsigned long long)atomic_load(&g_stats.conns_open), (unsigned long long)atomic_load(&g_stats.conns_open),
        (unsigned long long)hits, (unsigned long long)miss, hits + miss ? (double)hits / (hits + miss) : 0.0);
}

void stats_prometheus(UBuf* o) {
    ubuf_printf(o,
        "# HELP qbix_requests_total HTTP requests served.\n# TYPE qbix_requests_total counter\n"
        "qbix_requests_total{class=\"2xx\"} %llu\nqbix_requests_total{class=\"3xx\"} %llu\n"
        "qbix_requests_total{class=\"4xx\"} %llu\nqbix_requests_total{class=\"5xx\"} %llu\n"
        "# HELP qbix_php_requests_total Requests run in the PHP plane.\n# TYPE qbix_php_requests_total counter\nqbix_php_requests_total %llu\n"
        "# HELP qbix_bytes_out_total Response bytes.\n# TYPE qbix_bytes_out_total counter\nqbix_bytes_out_total %llu\n"
        "# HELP qbix_request_seconds_total Summed request time.\n# TYPE qbix_request_seconds_total counter\nqbix_request_seconds_total %.6f\n"
        "# HELP qbix_connections Open connections.\n# TYPE qbix_connections gauge\nqbix_connections %llu\n"
        "# HELP qbix_php_busy PHP threads running a request.\n# TYPE qbix_php_busy gauge\nqbix_php_busy %llu\n"
        "# HELP qbix_static_cache_hits_total Static response cache hits.\n# TYPE qbix_static_cache_hits_total counter\nqbix_static_cache_hits_total %llu\n"
        "# HELP qbix_resident_bytes Resident memory.\n# TYPE qbix_resident_bytes gauge\nqbix_resident_bytes %ld\n"
        "# HELP qbix_uptime_seconds Seconds since start.\n# TYPE qbix_uptime_seconds gauge\nqbix_uptime_seconds %.0f\n",
        (unsigned long long)atomic_load(&g_stats.s2xx), (unsigned long long)atomic_load(&g_stats.s3xx),
        (unsigned long long)atomic_load(&g_stats.s4xx), (unsigned long long)atomic_load(&g_stats.s5xx),
        (unsigned long long)atomic_load(&g_stats.php), (unsigned long long)atomic_load(&g_stats.bytes_out),
        atomic_load(&g_stats.us_total) / 1e6, (unsigned long long)atomic_load(&g_stats.conns_open),
        (unsigned long long)atomic_load(&g_stats.php_busy), (unsigned long long)atomic_load(&g_stats.cache_hits),
        rss_kb() * 1024, now_s() - g_stats.started);

    /* proxy backend metrics (only when proxy mode is active) */
    if (g_cfg.n_backends > 0) {
        ubuf_adds(o, "# HELP proxy_requests_forwarded_total Requests forwarded to backend.\n# TYPE proxy_requests_forwarded_total counter\n");
        ubuf_adds(o, "# HELP proxy_requests_rejected_total Requests rejected by validation.\n# TYPE proxy_requests_rejected_total counter\n");
        ubuf_adds(o, "# HELP proxy_errors_total Backend connection/protocol errors.\n# TYPE proxy_errors_total counter\n");
        ubuf_adds(o, "# HELP proxy_request_seconds_total Summed proxy forwarding time.\n# TYPE proxy_request_seconds_total counter\n");
        for (int i = 0; i < g_cfg.n_backends; i++) {
            const char* name = g_cfg.backends[i].name;
            ubuf_printf(o, "proxy_requests_forwarded_total{backend=\"%s\"} %llu\n", name,
                        (unsigned long long)atomic_load(&g_proxy_stats[i].forwarded));
            ubuf_printf(o, "proxy_requests_rejected_total{backend=\"%s\"} %llu\n", name,
                        (unsigned long long)atomic_load(&g_proxy_stats[i].rejected));
            ubuf_printf(o, "proxy_errors_total{backend=\"%s\"} %llu\n", name,
                        (unsigned long long)atomic_load(&g_proxy_stats[i].errors));
            ubuf_printf(o, "proxy_request_seconds_total{backend=\"%s\"} %.6f\n", name,
                        atomic_load(&g_proxy_stats[i].us_total) / 1e6);
        }
    }
}
