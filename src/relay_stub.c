/* relay_stub.c — proxy-only build: no relay child. */
#include "userver.h"
int  relay_start(void)                                                  { return -1; }
void relay_stop(void)                                                   {}
int  relay_enabled(void)                                                { return 0; }
int  relay_dispatch(const char* json, char** result)                    { (void)json; (void)result; return -1; }
int  relay_worker_main(int fd)                                          { (void)fd; return 1; }
