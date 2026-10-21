/* h2_stub.c — proxy-only build: no HTTP/2 support. */
#include "userver.h"
int  h2_start(UConn* c)                                     { (void)c; return -1; }
void h2_on_data(UConn* c)                                   { (void)c; }
void h2_pump(UConn* c)                                      { (void)c; }
void h2_complete(UConn* c, UReq* req, UResp* r, double t0)  { (void)c; (void)req; (void)r; (void)t0; }
int  h2_busy(UConn* c)                                      { (void)c; return 0; }
void h2_mark_gone(UConn* c)                                 { (void)c; }
void h2_release(UConn* c, int32_t id)                       { (void)c; (void)id; }
void h2_free(UConn* c)                                      { (void)c; }
