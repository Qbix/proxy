/* process_stub.c — proxy-only build: no PHP process mode. */
#include "userver.h"
int  proc_start(int nworkers)                             { (void)nworkers; return -1; }
void proc_stop(void)                                      {}
int  proc_enabled(void)                                   { return 0; }
int  proc_dispatch(UConn* c, UReq* req, double t0)        { (void)c; (void)req; (void)t0; return -1; }
int  proc_worker_main(int fd)                             { (void)fd; return 1; }
