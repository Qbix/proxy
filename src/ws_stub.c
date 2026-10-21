/* ws_stub.c — proxy-only build: no WebSocket support. */
#include "userver.h"
_Atomic int g_ws_dash_subs;
void ws_init(void)                                                              {}
int  ws_upgrade(UConn* c, UReq* req, const char* ch, int d)                    { (void)c; (void)req; (void)ch; (void)d; return 0; }
void ws_on_data(UConn* c)                                                      { (void)c; }
void ws_conn_closed(UConn* c)                                                  { (void)c; }
int  ws_post_valid(UConn* c, uint64_t id)                                      { (void)c; (void)id; return 0; }
void ws_tick(UConn* c, double now)                                             { (void)c; (void)now; }
void ws_dashboard_request(const char* method, const char* uri, int st, double ms) { (void)method; (void)uri; (void)st; (void)ms; }
int  ws_command(const char* json, size_t n)                                    { (void)json; (void)n; return -1; }
void ws_stats_json(UBuf* out)                                                  { (void)out; }
