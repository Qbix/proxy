/* static_stub.c — proxy-only build: no static file serving. */
#include "userver.h"
int  static_serve(UReq* req, UResp* resp, const char* path, int head) { (void)req; (void)path; (void)head; route_error_page(resp, 503, NULL); return 1; }
void static_cache_clear(void)           {}
const char* static_mime(const char* ext) { (void)ext; return "application/octet-stream"; }
int  static_ext_allowed(const char* ext) { (void)ext; return 0; }
void metrics_inject(UBuf* body, const char* ctype, const UReq* req) { (void)body; (void)ctype; (void)req; }
