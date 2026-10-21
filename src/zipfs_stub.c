/* zipfs_stub.c — proxy-only build: no ZIP filesystem. */
#include "userver.h"
int             zipfs_init(const char* path)                                       { (void)path; return 0; }
int             zipfs_active(void)                                                 { return 0; }
const ZipEntry* zipfs_lookup(const char* path)                                     { (void)path; return NULL; }
int             zipfs_serve_static(const ZipEntry* e, UReq* req, UResp* resp)      { (void)e; (void)req; (void)resp; return 0; }
char*           zipfs_extract_php(const ZipEntry* e)                               { (void)e; return NULL; }
void            zipfs_foreach(void (*fn)(const char*, const ZipEntry*, void*), void* arg) { (void)fn; (void)arg; }
int             zipfs_count(void)                                                  { return 0; }
int             zipfs_pack(const char* dir, const char* output)                    { (void)dir; (void)output; return -1; }
ssize_t         zipfs_read(const ZipEntry* e, uint8_t** out)                       { (void)e; (void)out; return -1; }
void            zipfs_free(void)                                                   {}
