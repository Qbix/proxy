/* php_stub.c — the build without a PHP plane (make PHP=0). */
#include "userver.h"
int  php_start(void) { return -1; }
void php_stop(void) {}
int  php_enabled(void) { return 0; }
int  php_dispatch(UConn* c, UReq* req, const char* s, const char* pi, double t0) { (void)c; (void)req; (void)s; (void)pi; (void)t0; return 0; }
const char* php_control_script(void) { return 0; }
const char* php_ws_script(const char* n) { (void)n; return 0; }
int php_ws_thread_start(const char* s, int fd, const char* i, const char* u) { (void)s; (void)fd; (void)i; (void)u; return -1; }
int php_shared_lookup(const char* k, UBuf* o) { (void)k; (void)o; return 0; }
