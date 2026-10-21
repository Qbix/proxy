/* tls_stub.c — proxy-only build: no TLS termination.
   The proxy forwards to local backends (PHP-FPM over Unix socket or
   localhost); nginx / the existing stack handles TLS. */
#include "userver.h"
int     tls_init(void)                                { return 0; /* HTTPS port 0 = off */ }
void*   tls_new(int fd)                               { (void)fd; return NULL; }
void    tls_free(void* ssl)                           { (void)ssl; }
int     tls_handshake(void* ssl, int* want_write)     { (void)ssl; (void)want_write; return -1; }
int     tls_is_h2(void* ssl)                          { (void)ssl; return 0; }
ssize_t tls_read(void* ssl, void* buf, size_t n, int* w)  { (void)ssl; (void)buf; (void)n; (void)w; return -1; }
ssize_t tls_write(void* ssl, const void* buf, size_t n, int* r) { (void)ssl; (void)buf; (void)n; (void)r; return -1; }
void    tls_acme_start(void)                          {}
