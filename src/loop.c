/* loop.c — event loops, connections, output, shutdown, main().
 *
 * One thread per loop; each loop owns an epoll set and its own listening
 * socket bound with SO_REUSEPORT, so the kernel spreads accepts and no
 * connection ever moves between threads. A request that goes to the PHP
 * plane leaves the connection BUSY; the PHP thread hands the finished
 * response back through the loop's completion queue and eventfd, and the
 * loop writes it. Responses go out with send(2), files with sendfile(2).
 *
 * SIGTERM / SIGINT: stop accepting, let in-flight requests finish and
 * output drain for up to five seconds, then exit.
 *
 * --app mode: bind localhost, optionally open the system browser, and
 * shut down after app_idle_timeout seconds of zero connections.
 */
#include "userver.h"
#include "platform.h"
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#ifdef __COSMOPOLITAN__
#  include "cosmo_compat.h"
#else
#  include <sys/epoll.h>
#  include <sys/eventfd.h>
#  include <sys/sendfile.h>
#endif

typedef struct Completion {
    struct Completion* next;
    UConn* c; UReq* req; UResp resp; double t0;
} Completion;

typedef struct WsPost {
    struct WsPost* next;
    UConn* c; uint64_t id; char* data; size_t len; int close;
} WsPost;

typedef struct ULoop {
    int id, epfd, lfd, efd, lfd_tls;
    pthread_t th;
    pthread_mutex_t mu;
    Completion *cq_head, *cq_tail;
    WsPost *wq_head, *wq_tail;     /* WebSocket frames from other threads */
    UConn* live;
    UConn* dead;     /* closed this iteration; freed after its events are done */
    int nconns;
} ULoop;

static ULoop* g_loops;
static volatile sig_atomic_t g_stopping;
static double g_stop_deadline;
static _Atomic uint64_t g_conn_ids;
static char MARK_LISTEN, MARK_LISTEN_TLS, MARK_EVENT;
static int g_https_port;
static double g_app_idle_since;   /* timestamp when total connections hit 0 (app mode) */

static void conn_close(UConn* c);
static void conn_process(UConn* c);
static void conn_flush(UConn* c);

static void set_events(UConn* c, int want_write) {
    if (c->want_write == want_write) return;
    c->want_write = want_write;
    struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP | (want_write ? EPOLLOUT : 0), .data.ptr = c };
    epoll_ctl(c->loop->epfd, EPOLL_CTL_MOD, c->fd, &ev);
}

static void out_push(UConn* c, UOut* o) {
    o->next = NULL;
    if (c->out_tail) c->out_tail->next = o; else c->out_head = o;
    c->out_tail = o;
}

/* Serialise a response onto the connection's output queue. */
void conn_send_response(UConn* c, UReq* req, UResp* resp, double t0) {
    int st = resp->status;
    int keep = req && req->keep_alive && !resp->close && st < 500 && c->requests < g_cfg.keepalive_max && !g_stopping;
    UBuf h = {0};
    ubuf_printf(&h, "HTTP/1.1 %d %s\r\n", st, http_reason(st));
    if (!resp->head.data || strncmp(resp->head.data, "Server:", 7) != 0) {
        if (!(resp->head.data && strstr(resp->head.data, "\r\nServer:"))) ubuf_printf(&h, "Server: %s\r\n", SERVER_TAG);
    }
    if (resp->head.len) ubuf_add(&h, resp->head.data, resp->head.len);
    int bodyless = st == 204 || st == 304 || (st >= 100 && st < 200);
    if (!resp->has_ctype && !bodyless) ubuf_adds(&h, "Content-Type: text/plain; charset=utf-8\r\n");
    size_t blen = resp->file_fd >= 0 ? resp->file_len : resp->body.len;
    if (st != 204 && !(st >= 100 && st < 200)) ubuf_printf(&h, "Content-Length: %zu\r\n", bodyless ? (size_t)0 : blen);
    ubuf_printf(&h, "Connection: %s\r\n\r\n", keep ? "keep-alive" : "close");
    int send_body = !resp->head_only && !bodyless && !(req && !strcmp(req->method, "HEAD"));
    if (send_body && resp->body.len && resp->file_fd < 0) ubuf_add(&h, resp->body.data, resp->body.len);

    UOut* o = calloc(1, sizeof *o);
    o->data = h.data; o->len = h.len; o->fd = -1;
    out_push(c, o);
    if (send_body && resp->file_fd >= 0 && resp->file_len) {
        UOut* f = calloc(1, sizeof *f);
        f->fd = resp->file_fd; f->foff = resp->file_off; f->flen = resp->file_len;
        resp->file_fd = -1;
        out_push(c, f);
    }
    double ms = (now_s() - t0) * 1000;
    stats_record(st, blen, ms, resp->from_php, req ? req->method : NULL, req ? req->uri : NULL);
    if (req) alog_write(req, st, blen, ms);
    if (!keep) c->close_after = 1;
    conn_flush(c);
}

/* send(2), or SSL_write on a TLS connection */
static ssize_t io_send(UConn* c, const char* d, size_t n) {
    if (!c->ssl) return send(c->fd, d, n, MSG_NOSIGNAL);
    int wr; return tls_write(c->ssl, d, n, &wr);
}

static void conn_flush(UConn* c) {
    while (c->out_head) {
        UOut* o = c->out_head;
        if (o->fd >= 0 && c->ssl) {
            /* no sendfile under TLS: read the file a slice at a time */
            if (o->off == o->len && o->flen) {
                size_t want = o->flen < (64u << 10) ? o->flen : (64u << 10);
                if (!o->data) o->data = malloc(64u << 10);
                ssize_t r = pread(o->fd, o->data, want, o->foff);
                if (r <= 0) { conn_close(c); return; }
                o->len = (size_t)r; o->off = 0; o->foff += r; o->flen -= (size_t)r;
            }
            if (o->off == o->len && !o->flen) { close(o->fd); o->fd = -1; }
        }
        if (o->fd < 0 || c->ssl) {
            while (o->off < o->len) {
                ssize_t n = io_send(c, o->data + o->off, o->len - o->off);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) { set_events(c, 1); return; }
                    c->close_after = 1; c->state = CONN_CLOSING; conn_close(c); return;
                }
                o->off += (size_t)n;
            }
            if (o->fd >= 0) continue;   /* the next slice of the file */
        } else {
            while (o->flen) {
                ssize_t n = sendfile(c->fd, o->fd, &o->foff, o->flen > (1 << 20) ? (1 << 20) : o->flen);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) { set_events(c, 1); return; }
                    conn_close(c); return;
                }
                if (n == 0) { conn_close(c); return; }
                o->flen -= (size_t)n;
            }
            close(o->fd); o->fd = -1;
        }
        c->out_head = o->next; if (!c->out_head) c->out_tail = NULL;
        free(o->data); free(o);
    }
    set_events(c, 0);
    if (c->close_after) { conn_close(c); return; }
}

static void conn_free_out(UConn* c) {
    UOut* o = c->out_head;
    while (o) { UOut* n = o->next; if (o->fd >= 0) close(o->fd); free(o->data); free(o); o = n; }
    c->out_head = c->out_tail = NULL;
}

static void conn_close(UConn* c) {
    if (c->state == CONN_BUSY && c->busy_req) atomic_store(&c->busy_req->gone, 1);
    if (c->jobs > 0) h2_mark_gone(c);
    if (c->state == CONN_BUSY || c->jobs > 0) { c->close_after = 1; c->state = CONN_CLOSING; if (c->fd >= 0) shutdown(c->fd, SHUT_RDWR); return; }
    if (c->fd < 0) return;
    if (c->ws) ws_conn_closed(c);
    if (c->h2) h2_free(c);
    if (c->ssl) { tls_free(c->ssl); c->ssl = NULL; }
    epoll_ctl(c->loop->epfd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd); c->fd = -1;
    conn_free_out(c);
    ubuf_free(&c->in);
    ULoop* L = c->loop;
    if (c->prev_live) c->prev_live->next_live = c->next_live; else L->live = c->next_live;
    if (c->next_live) c->next_live->prev_live = c->prev_live;
    L->nconns--;
    atomic_fetch_sub(&g_stats.conns_open, 1);
    /* not free(c) yet: later events in this epoll batch may still name c */
    c->next_live = L->dead; L->dead = c;
}

/* Parse and run every complete request in the buffer, in order. */
static const char H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

static void conn_process(UConn* c) {
    /* h2c with prior knowledge: the HTTP/2 preface instead of a request line */
    if (!c->ssl && !c->requests && !g_cfg.no_http2 && c->in.len && !memcmp(c->in.data, H2_PREFACE, c->in.len < 24 ? c->in.len : 24)) {
        if (c->in.len < 24) return;
        if (h2_start(c) == 0) { h2_on_data(c); return; }
    }
    while (c->fd >= 0 && c->state == CONN_READING && !c->close_after && !c->out_head) {
        UReq* req = calloc(1, sizeof *req);
        UResp resp; uresp_init(&resp);
        int r = http_parse(c, req, &resp);
        if (r == 0) { free(req); uresp_free(&resp); return; }
        double t0 = now_s();
        if (r < 0) {
            /* refused at parse time: answer and close */
            UReq dummy; memset(&dummy, 0, sizeof dummy);
            dummy.method = "GET"; dummy.uri = "-"; dummy.version[0] = '1'; dummy.version[1] = '.'; dummy.version[2] = '1';
            snprintf(dummy.remote_ip, sizeof dummy.remote_ip, "%s", c->ip);
            resp.close = 1;
            conn_send_response(c, &dummy, &resp, t0);
            uresp_free(&resp); ureq_free(req); free(req);
            return;
        }
        c->requests++;
        c->last_active = t0;
        req->tls = c->ssl != NULL;
        int ready = route_request(c, req, &resp);
        if (ready == 2) {   /* upgraded to a WebSocket: no HTTP response, no more requests */
            uresp_free(&resp); ureq_free(req); free(req);
            return;
        }
        if (ready) {
            conn_send_response(c, req, &resp, t0);
            uresp_free(&resp); ureq_free(req); free(req);
            if (c->fd < 0) return;
        } else {
            uresp_free(&resp);
            c->state = CONN_BUSY;   /* the PHP plane owns req now */
            c->busy_req = req;
            return;
        }
    }
}

/* Called from a PHP thread: queue the response for the owning loop. */
void loop_complete(UConn* c, UReq* req, UResp* resp, double t0) {
    Completion* q = calloc(1, sizeof *q);
    q->c = c; q->req = req; q->resp = *resp; q->t0 = t0;
    ULoop* L = c->loop;
    pthread_mutex_lock(&L->mu);
    if (L->cq_tail) L->cq_tail->next = q; else L->cq_head = q;
    L->cq_tail = q;
    pthread_mutex_unlock(&L->mu);
    uint64_t one = 1;
    if (write(L->efd, &one, sizeof one) < 0) { /* eventfd full is impossible at this rate */ }
}

static void queue_bytes(UConn* c, const char* d, size_t n) {
    UOut* o = calloc(1, sizeof *o);
    o->data = malloc(n ? n : 1); memcpy(o->data, d, n); o->len = n; o->fd = -1;
    out_push(c, o);
}

/* for ws.c, on the owner loop */
void conn_write(UConn* c, const void* d, size_t n) { if (c->fd < 0) return; queue_bytes(c, d, n); conn_flush(c); }
void conn_close_now(UConn* c) { c->close_after = 1; conn_close(c); }

/* any thread: a WebSocket frame (or a close) for a connection on loop L */
void loop_ws_post(UConn* c, uint64_t id, char* data, size_t n, int close) {
    WsPost* p = calloc(1, sizeof *p);
    p->c = c; p->id = id; p->data = data; p->len = n; p->close = close;
    ULoop* L = c->loop;
    pthread_mutex_lock(&L->mu);
    if (L->wq_tail) L->wq_tail->next = p; else L->wq_head = p;
    L->wq_tail = p;
    pthread_mutex_unlock(&L->mu);
    uint64_t one = 1;
    if (write(L->efd, &one, sizeof one) < 0) { }
}

/* A streamed PHP response: status -1 is the head, -2 a chunk, -3 the end. */
static void stream_part(UConn* c, Completion* q) {
    UResp* r = &q->resp;
    if (r->status == -1) {
        int st = r->from_php;
        c->stream_keep = q->req && q->req->keep_alive && c->requests < g_cfg.keepalive_max && !g_stopping;
        UBuf h = {0};
        ubuf_printf(&h, "HTTP/1.1 %d %s\r\nServer: %s\r\n", st, http_reason(st), SERVER_TAG);
        if (r->head.len) ubuf_add(&h, r->head.data, r->head.len);
        ubuf_printf(&h, "Transfer-Encoding: chunked\r\nConnection: %s\r\n\r\n", c->stream_keep ? "keep-alive" : "close");
        c->stream_status = st;
        queue_bytes(c, h.data, h.len); ubuf_free(&h);
    } else {
        if (r->body.len) {
            char sz[32]; int n = snprintf(sz, sizeof sz, "%zx\r\n", r->body.len);
            UBuf b = {0}; ubuf_add(&b, sz, (size_t)n); ubuf_add(&b, r->body.data, r->body.len); ubuf_add(&b, "\r\n", 2);
            queue_bytes(c, b.data, b.len); ubuf_free(&b);
        }
        if (r->status == -3) {
            queue_bytes(c, "0\r\n\r\n", 5);
            stats_record(c->stream_status, 0, (now_s() - q->t0) * 1000, 1, q->req ? q->req->method : NULL, q->req ? q->req->uri : NULL);
            if (!c->stream_keep) c->close_after = 1;
        }
    }
    conn_flush(c);
}

static void drain_completions(ULoop* L) {
    uint64_t v; if (read(L->efd, &v, sizeof v) < 0) { }
    pthread_mutex_lock(&L->mu);
    Completion* q = L->cq_head; L->cq_head = L->cq_tail = NULL;
    WsPost* wp = L->wq_head; L->wq_head = L->wq_tail = NULL;
    pthread_mutex_unlock(&L->mu);
    while (wp) {
        WsPost* n = wp->next;
        if (ws_post_valid(wp->c, wp->id)) {
            if (wp->close) conn_close_now(wp->c);
            else conn_write(wp->c, wp->data, wp->len);
        }
        free(wp->data); free(wp);
        wp = n;
    }
    while (q) {
        Completion* n = q->next;
        UConn* c = q->c;
        int st = q->resp.status;
        int final = st != -1 && st != -2;
        int dead = c->state == CONN_CLOSING;
        if (final) c->busy_req = NULL;
        if (c->h2) {
            if (final) { c->jobs--; h2_release(c, q->resp.stream); }
            if (!dead) h2_complete(c, q->req, &q->resp, q->t0);
            else if (!c->jobs) { c->state = CONN_READING; conn_close(c); }
        } else if (dead) {
            if (final) { c->state = CONN_READING; c->close_after = 1; conn_close(c); }
        } else if (st < 0) {
            if (final) c->state = CONN_READING;
            stream_part(c, q);
            if (final && c->fd >= 0 && !c->out_head) conn_process(c);
        } else if (q->resp.upgrade) {
            /* control.php accepted /Q/ws: the handshake and the rest are native */
            c->state = CONN_READING;
            stats_record(101, 0, (now_s() - q->t0) * 1000, 0, q->req->method, q->req->uri);
            if (!ws_upgrade(c, q->req, q->resp.upgrade, 0)) {
                UResp bad; uresp_init(&bad); route_send_simple(&bad, 400, "Bad WebSocket handshake", NULL); bad.close = 1;
                conn_send_response(c, q->req, &bad, q->t0); uresp_free(&bad);
            }
        } else {
            c->state = CONN_READING;
            conn_send_response(c, q->req, &q->resp, q->t0);
            if (c->fd >= 0 && !c->out_head) conn_process(c);
        }
        uresp_free(&q->resp);
        if (q->req) { ureq_free(q->req); free(q->req); }
        free(q);
        q = n;
    }
}

static int make_listener(int port) {
    int fd = socket(strchr(g_cfg.host, ':') ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    if (strchr(g_cfg.host, ':')) {
        struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_port = htons((uint16_t)port) };
        inet_pton(AF_INET6, g_cfg.host, &a.sin6_addr);
        if (bind(fd, (struct sockaddr*)&a, sizeof a) < 0) { close(fd); return -1; }
    } else {
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
        if (inet_pton(AF_INET, g_cfg.host, &a.sin_addr) != 1) a.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd, (struct sockaddr*)&a, sizeof a) < 0) { close(fd); return -1; }
    }
    if (listen(fd, 4096) < 0) { close(fd); return -1; }
    return fd;
}

static void do_accept(ULoop* L, int tls) {
    for (;;) {
        struct sockaddr_storage sa; socklen_t sl = sizeof sa;
        int fd = accept4(tls ? L->lfd_tls : L->lfd, (struct sockaddr*)&sa, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) return;
        int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        UConn* c = calloc(1, sizeof *c);
        c->fd = fd; c->loop = L; c->state = CONN_READING; c->last_active = now_s();
        c->id = atomic_fetch_add(&g_conn_ids, 1);
        if (sa.ss_family == AF_INET) {
            struct sockaddr_in* a = (struct sockaddr_in*)&sa; inet_ntop(AF_INET, &a->sin_addr, c->ip, sizeof c->ip); c->port = ntohs(a->sin_port);
        } else {
            struct sockaddr_in6* a = (struct sockaddr_in6*)&sa; inet_ntop(AF_INET6, &a->sin6_addr, c->ip, sizeof c->ip); c->port = ntohs(a->sin6_port);
        }
        c->local_port = tls ? g_https_port : g_cfg.port;
        if (tls) {
            c->ssl = tls_new(fd);
            if (!c->ssl) { close(fd); free(c); continue; }
            c->tls_hs = 1;
        }
        c->next_live = L->live; if (L->live) L->live->prev_live = c; L->live = c;
        L->nconns++;
        atomic_fetch_add(&g_stats.conns_open, 1); atomic_fetch_add(&g_stats.conns_total, 1);
        struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP, .data.ptr = c };
        epoll_ctl(L->epfd, EPOLL_CTL_ADD, fd, &ev);
    }
}

/* drive a TLS handshake; 1 when done (and ALPN may have chosen h2) */
static int tls_progress(UConn* c) {
    int ww;
    int r = tls_handshake(c->ssl, &ww);
    if (r < 0) { conn_close(c); return 0; }
    if (r == 0) { set_events(c, ww); return 0; }
    c->tls_hs = 0;
    set_events(c, 0);
    if (tls_is_h2(c->ssl) && !g_cfg.no_http2 && h2_start(c) != 0) { conn_close(c); return 0; }
    return 1;
}

static void on_readable(UConn* c) {
    char tmp[65536];
    if (c->tls_hs && !tls_progress(c)) return;
    for (;;) {
        ssize_t n;
        if (c->ssl) { int ww; n = tls_read(c->ssl, tmp, sizeof tmp, &ww); if (n < 0 && ww) set_events(c, 1); }
        else n = recv(c->fd, tmp, sizeof tmp, 0);
        if (n > 0) {
            ubuf_add(&c->in, tmp, (size_t)n);
            c->last_active = now_s();
            if (c->in.len > g_cfg.max_post + g_cfg.max_header + 65536) { c->close_after = 1; conn_close(c); return; }
            continue;
        }
        if (n == 0) {
            if (c->state == CONN_BUSY) { c->state = CONN_CLOSING; return; }   /* finish, then close */
            if (c->out_head) { c->close_after = 1; return; }
            conn_close(c); return;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        conn_close(c); return;
    }
    if (c->h2) { h2_on_data(c); return; }
    if (c->ws) { ws_on_data(c); return; }
    if (c->state == CONN_READING) conn_process(c);
}

static void sweep(ULoop* L, double now) {
    UConn* c = L->live;
    while (c) {
        UConn* n = c->next_live;
        if (c->ws) { if (g_stopping) conn_close(c); else ws_tick(c, now); }
        else if (c->h2) { if (!c->out_head && !h2_busy(c) && (g_stopping || now - c->last_active > g_cfg.keepalive_timeout)) conn_close(c); }
        else if (c->state == CONN_READING && !c->out_head && now - c->last_active > g_cfg.keepalive_timeout) conn_close(c);
        else if (g_stopping && c->state == CONN_READING && !c->out_head && c->in.len == 0) conn_close(c);
        c = n;
    }
}

static void* loop_main(void* arg) {
    ULoop* L = arg;
    struct epoll_event evs[256];
    double last_sweep = now_s();
    for (;;) {
        int n = epoll_wait(L->epfd, evs, 256, 250);
        for (int i = 0; i < n; i++) {
            void* p = evs[i].data.ptr;
            if (p == &MARK_LISTEN) { if (!g_stopping) do_accept(L, 0); continue; }
            if (p == &MARK_LISTEN_TLS) { if (!g_stopping) do_accept(L, 1); continue; }
            if (p == &MARK_EVENT) { drain_completions(L); continue; }
            UConn* c = p;
            if (c->fd < 0) continue;
            if (evs[i].events & (EPOLLERR)) { conn_close(c); continue; }
            if (c->tls_hs) { if (evs[i].events & (EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLHUP)) on_readable(c); continue; }
            if (evs[i].events & EPOLLOUT) {
                conn_flush(c); if (c->fd < 0) continue;
                if (!c->out_head && c->h2) h2_pump(c);
                else if (!c->out_head && c->state == CONN_READING && !c->ws) conn_process(c);
                if (c->fd < 0) continue;
            }
            if (evs[i].events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) on_readable(c);
        }
        while (L->dead) { UConn* d = L->dead; L->dead = d->next_live; free(d); }
        double now = now_s();
        if (g_stopping && L->lfd >= 0) { epoll_ctl(L->epfd, EPOLL_CTL_DEL, L->lfd, NULL); close(L->lfd); L->lfd = -1; }
        if (g_stopping && L->lfd_tls >= 0) { epoll_ctl(L->epfd, EPOLL_CTL_DEL, L->lfd_tls, NULL); close(L->lfd_tls); L->lfd_tls = -1; }
        if (now - last_sweep >= 1 || g_stopping) { sweep(L, now); last_sweep = now; }
        /* app mode idle shutdown: when all connections are gone, start the timer */
        if (g_cfg.app_mode && !g_stopping) {
            if (L->nconns == 0) {
                if (g_app_idle_since == 0) g_app_idle_since = now;
                else if (now - g_app_idle_since > g_cfg.app_idle_timeout) {
                    fprintf(stderr, "[app] no connections for %.0fs, shutting down\n", g_cfg.app_idle_timeout);
                    g_stop_deadline = now + 1;
                    g_stopping = 1;
                }
            } else {
                g_app_idle_since = 0;
            }
        }
        if (g_stopping && (L->nconns == 0 || now > g_stop_deadline)) break;
    }
    return NULL;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (config_load(argc, argv) != 0) return 1;

    /* Worker child: run PHP in a loop, talking to the parent over ctrl_fd */
    if (g_cfg.process_worker_fd > 0)
        return proc_worker_main(g_cfg.process_worker_fd);

    /* Relay child: run relay PHP scripts over the control fd */
    if (g_cfg.relay_worker_fd > 0)
        return relay_worker_main(g_cfg.relay_worker_fd);

    /* --pack=DIR: bundle app files into a packed binary and exit */
    if (g_cfg.pack_dir) {
        const char* out = g_cfg.pack_output ? g_cfg.pack_output : "./myapp";
        return zipfs_pack(g_cfg.pack_dir, out) == 0 ? 0 : 1;
    }

    /* Detect appended ZIP (redbean-style) */
    {
        char self[PATH_MAX];
        ssize_t sn = readlink("/proc/self/exe", self, sizeof self - 1);
        if (sn > 0) { self[sn] = 0; zipfs_init(self); }
    }

    /* Load app.json from ZIP if present (after zipfs_init) */
    if (zipfs_active()) load_app_json();

    g_stats.started = now_s();

    sigset_t set; sigemptyset(&set); sigaddset(&set, SIGTERM); sigaddset(&set, SIGINT); sigaddset(&set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &set, NULL);   /* threads inherit the mask; main waits */

    if (g_cfg.process_mode) {
        int nw = g_cfg.process_workers > 0 ? g_cfg.process_workers : (int)(sysconf(_SC_NPROCESSORS_ONLN) > 0 ? sysconf(_SC_NPROCESSORS_ONLN) : 1);
        if (proc_start(nw) != 0)
            fprintf(stderr, "[process] process-mode workers failed; falling back to threads\n");
    }

    /* Start the relay sibling process (SMTP / SMS credential isolation) */
    if (relay_start() == 0)
        fprintf(stderr, "[relay] relay process ready\n");

    if (!proc_enabled() && g_cfg.php_threads > 0 && php_start() != 0)
        fprintf(stderr, "[php] PHP plane unavailable; .php requests will get 503\n");

    ws_init();
    g_https_port = tls_init();
    tls_acme_start();
    g_loops = calloc((size_t)g_cfg.threads, sizeof *g_loops);
    for (int i = 0; i < g_cfg.threads; i++) {
        ULoop* L = &g_loops[i];
        L->id = i; pthread_mutex_init(&L->mu, NULL);
        L->lfd = make_listener(g_cfg.port);
        if (L->lfd < 0) { fprintf(stderr, "cannot listen on %s:%d: %s\n", g_cfg.host, g_cfg.port, strerror(errno)); return 1; }
        /* app mode with port 0: read back the kernel-assigned port */
        if (g_cfg.app_mode && g_cfg.port == 0 && i == 0) {
            struct sockaddr_in sa; socklen_t sl = sizeof sa;
            if (getsockname(L->lfd, (struct sockaddr*)&sa, &sl) == 0)
                g_cfg.port = ntohs(sa.sin_port);
        }
        L->lfd_tls = g_https_port ? make_listener(g_https_port) : -1;
        if (g_https_port && L->lfd_tls < 0) { fprintf(stderr, "[HTTPS] Could not bind to %s:%d — %s\n", g_cfg.host, g_https_port, strerror(errno)); g_https_port = 0; }
        L->epfd = epoll_create1(EPOLL_CLOEXEC);
        L->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &MARK_LISTEN };
        epoll_ctl(L->epfd, EPOLL_CTL_ADD, L->lfd, &ev);
        struct epoll_event ev2 = { .events = EPOLLIN, .data.ptr = &MARK_EVENT };
        epoll_ctl(L->epfd, EPOLL_CTL_ADD, L->efd, &ev2);
        if (L->lfd_tls >= 0) { struct epoll_event ev3 = { .events = EPOLLIN, .data.ptr = &MARK_LISTEN_TLS }; epoll_ctl(L->epfd, EPOLL_CTL_ADD, L->lfd_tls, &ev3); }
    }
    for (int i = 0; i < g_cfg.threads; i++) pthread_create(&g_loops[i].th, NULL, loop_main, &g_loops[i]);
    if (proc_enabled())
        fprintf(stderr, "%s listening on %s:%d, root %s, %d loop thread(s), process mode (%d workers)\n",
                SERVER_TAG, g_cfg.host, g_cfg.port, g_cfg.root, g_cfg.threads, g_cfg.process_workers);
    else
        fprintf(stderr, "%s listening on %s:%d, root %s, %d loop thread(s), %d PHP thread(s)%s\n",
                SERVER_TAG, g_cfg.host, g_cfg.port, g_cfg.root, g_cfg.threads, php_enabled() ? g_cfg.php_threads : 0,
                php_enabled() ? "" : " (PHP off)");
    if (g_https_port) fprintf(stderr, "[HTTPS] Listening on https://%s:%d%s\n", g_cfg.host, g_https_port, g_cfg.no_http2 ? "" : " (HTTP/2 and HTTP/1.1)");

    /* app mode: open the browser */
    if (g_cfg.app_mode && !g_cfg.app_no_open) {
        char url[256];
        snprintf(url, sizeof url, "http://127.0.0.1:%d/", g_cfg.port);
        if (plat_open_browser(url) == 0)
            fprintf(stderr, "[app] opened %s\n", url);
        else
            fprintf(stderr, "[app] could not open browser; navigate to %s\n", url);

        /* size the window if requested */
        if (g_cfg.app_width > 0 && g_cfg.app_height > 0) {
            usleep(500000);   /* give the browser a moment to open */
            int wx = g_cfg.app_x >= 0 ? g_cfg.app_x : 100;
            int wy = g_cfg.app_y >= 0 ? g_cfg.app_y : 100;
            plat_resize_window("", wx, wy, g_cfg.app_width, g_cfg.app_height);
        }
    }

    int sig = 0;
    for (;;) { if (sigwait(&set, &sig) == 0 && sig != SIGHUP) break; static_cache_clear(); }
    g_stop_deadline = now_s() + 5;
    g_stopping = 1;
    for (int i = 0; i < g_cfg.threads; i++) { uint64_t one = 1; if (write(g_loops[i].efd, &one, 8) < 0) {} }
    for (int i = 0; i < g_cfg.threads; i++) pthread_join(g_loops[i].th, NULL);
    if (proc_enabled()) proc_stop();
    relay_stop();
    php_stop();
    zipfs_free();
    return 0;
}
