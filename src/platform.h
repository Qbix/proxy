/* platform.h — portability layer for the U webserver.
 *
 * The event loop in loop.c is Linux-specific (epoll, eventfd,
 * SO_REUSEPORT, accept4, sendfile, /proc/self/exe).  This header
 * centralises the platform-dependent pieces so a kqueue or IOCP
 * backend can slot in without touching the rest of the server.
 *
 * For now only Linux is implemented.  macOS (kqueue) and Windows
 * (IOCP or WSAPoll) are stubbed so the compilation shape is visible.
 *
 * The contract: each backend provides the same set of functions,
 * using the same types.  Code outside this header and its
 * implementation file uses only these names.
 */
#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#ifndef _WIN32
#  include <fcntl.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#endif

/* ── event notifications ─────────────────────────────────────────── */

/* All backends deliver events through a callback with these flags: */
#define PLAT_IN   0x01   /* readable */
#define PLAT_OUT  0x02   /* writable */
#define PLAT_HUP  0x04   /* hangup / peer close */
#define PLAT_ERR  0x08   /* error */

/* ── platform detection ──────────────────────────────────────────── */

#if defined(__COSMOPOLITAN__)
/* Cosmopolitan libc provides Linux-compatible APIs (epoll, eventfd,
   sendfile, accept4, SO_REUSEPORT) on all platforms it targets. */
#  define PLAT_LINUX 1
#elif defined(__linux__)
#  define PLAT_LINUX 1
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#  define PLAT_BSD 1
#elif defined(_WIN32)
#  define PLAT_WIN32 1
#else
#  error "Unsupported platform; see platform.h"
#endif

/* ── cross-platform process spawning ─────────────────────────────── */

#ifdef PLAT_WIN32
/* Windows: CreateProcess + WSADuplicateSocket (not yet implemented) */
#  include <windows.h>
#  include <winsock2.h>
typedef HANDLE plat_pid_t;
#else
/* POSIX: posix_spawn + SCM_RIGHTS */
#  include <unistd.h>
#  include <spawn.h>
#  include <sys/types.h>
typedef pid_t plat_pid_t;
#endif

/* ── self-executable path ────────────────────────────────────────── */

/* Returns the path to the running executable, or NULL on failure.
   Caller frees the result. */
static inline char* plat_self_exe(void) {
#ifdef PLAT_LINUX
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0) return NULL;
    buf[n] = 0;
    char* r = malloc((size_t)n + 1);
    if (r) memcpy(r, buf, (size_t)n + 1);
    return r;
#elif defined(PLAT_BSD)
    /* macOS: _NSGetExecutablePath; FreeBSD: sysctl KERN_PROC_PATHNAME */
#  ifdef __APPLE__
    extern int _NSGetExecutablePath(char*, uint32_t*);
    char buf[4096]; uint32_t sz = sizeof buf;
    if (_NSGetExecutablePath(buf, &sz) == 0) {
        char* r = realpath(buf, NULL);
        return r;
    }
#  else
    /* FreeBSD */
    #include <sys/sysctl.h>
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
    char buf[4096]; size_t sz = sizeof buf;
    if (sysctl(mib, 4, buf, &sz, NULL, 0) == 0) return strdup(buf);
#  endif
    return NULL;
#elif defined(PLAT_WIN32)
    char buf[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, buf, sizeof buf);
    return n > 0 ? _strdup(buf) : NULL;
#else
    return NULL;
#endif
}

/* ── CPU count ───────────────────────────────────────────────────── */

static inline int plat_cpu_count(void) {
#ifdef PLAT_WIN32
    SYSTEM_INFO si; GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
#endif
}

/* ── socket helpers ──────────────────────────────────────────────── */

/* Set a file descriptor (or SOCKET on Windows) non-blocking. */
static inline int plat_set_nonblock(int fd) {
#ifdef PLAT_WIN32
    u_long mode = 1;
    return ioctlsocket((SOCKET)fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

/* ── browser launch ─────────────────────────────────────────────── */

/* Open a URL in the user's default browser.  Returns 0 on success. */
static inline int plat_open_browser(const char* url) {
#ifdef PLAT_LINUX
    pid_t pid;
    char* argv[] = { "xdg-open", (char*)url, NULL };
    extern char** environ;
    if (posix_spawnp(&pid, "xdg-open", NULL, NULL, argv, environ) != 0)
        return -1;
    return 0;  /* don't waitpid — xdg-open may outlive us */
#elif defined(__APPLE__)
    pid_t pid;
    char* argv[] = { "open", (char*)url, NULL };
    extern char** environ;
    if (posix_spawnp(&pid, "open", NULL, NULL, argv, environ) != 0)
        return -1;
    return 0;
#elif defined(PLAT_WIN32)
    /* ShellExecute returns >32 on success */
    return (INT_PTR)ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL) > 32 ? 0 : -1;
#else
    (void)url;
    return -1;
#endif
}

/* ── find a free TCP port ───────────────────────────────────────── */

/* Bind to port 0, read back the assigned port, close the socket.
   Returns the port number, or -1 on failure. */
static inline int plat_find_free_port(void) {
#ifdef PLAT_WIN32
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(s, (struct sockaddr*)&a, sizeof a) != 0) { closesocket(s); return -1; }
    int len = sizeof a;
    if (getsockname(s, (struct sockaddr*)&a, &len) != 0) { closesocket(s); return -1; }
    int port = ntohs(a.sin_port);
    closesocket(s);
    return port;
#else
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(s, (struct sockaddr*)&a, sizeof a) != 0) { close(s); return -1; }
    socklen_t len = sizeof a;
    if (getsockname(s, (struct sockaddr*)&a, &len) != 0) { close(s); return -1; }
    int port = ntohs(a.sin_port);
    close(s);
    return port;
#endif
}

/* ── window management (OS-level) ───────────────────────────────── */

/* Resize and position the frontmost browser window.
   Uses AppleScript on macOS, wmctrl/xdotool on Linux, PowerShell on Windows.
   Best-effort: returns 0 on success, -1 if the tool is not available. */
static inline int plat_resize_window(const char* title, int x, int y, int w, int h) {
#ifdef PLAT_LINUX
    /* Try wmctrl first (works with most window managers) */
    char cmd[512];
    snprintf(cmd, sizeof cmd,
        "wmctrl -r '%s' -e 0,%d,%d,%d,%d 2>/dev/null || "
        "xdotool search --name '%s' windowmove %d %d windowsize %d %d 2>/dev/null",
        title, x, y, w, h, title, x, y, w, h);
    return system(cmd) == 0 ? 0 : -1;
#elif defined(__APPLE__)
    char cmd[1024];
    snprintf(cmd, sizeof cmd,
        "osascript -e 'tell application \"System Events\" to tell (first process whose frontmost is true) to "
        "set position of front window to {%d, %d}' -e 'tell application \"System Events\" to tell "
        "(first process whose frontmost is true) to set size of front window to {%d, %d}' 2>/dev/null",
        x, y, w, h);
    (void)title;
    return system(cmd) == 0 ? 0 : -1;
#elif defined(PLAT_WIN32)
    (void)title;
    /* Find the foreground window and move it */
    HWND hw = GetForegroundWindow();
    if (!hw) return -1;
    return MoveWindow(hw, x, y, w, h, TRUE) ? 0 : -1;
#else
    (void)title; (void)x; (void)y; (void)w; (void)h;
    return -1;
#endif
}

/* ── automation / scripting APIs ─────────────────────────────────── */

/* Run an OS automation command (Automator/osascript on macOS,
   PowerShell on Windows, xdotool/wmctrl on Linux).
   Returns the exit code, or -1 if spawning failed.
   stdout/stderr go to the caller's buffer if non-NULL. */
static inline int plat_automate(const char* script, char* out, size_t out_cap) {
#ifdef PLAT_LINUX
    /* On Linux, the script is a shell command that can use xdotool, wmctrl, etc. */
    FILE* p = popen(script, "r");
    if (!p) return -1;
    if (out && out_cap > 0) {
        size_t total = 0;
        while (total < out_cap - 1) {
            size_t n = fread(out + total, 1, out_cap - 1 - total, p);
            if (n == 0) break;
            total += n;
        }
        out[total] = 0;
    }
    return pclose(p);
#elif defined(__APPLE__)
    /* Wrap in osascript if it looks like AppleScript, otherwise run as shell */
    char cmd[4096];
    if (strstr(script, "tell application") || strstr(script, "do shell script")) {
        snprintf(cmd, sizeof cmd, "osascript -e '%s'", script);
    } else {
        snprintf(cmd, sizeof cmd, "%s", script);
    }
    FILE* p = popen(cmd, "r");
    if (!p) return -1;
    if (out && out_cap > 0) {
        size_t total = 0;
        while (total < out_cap - 1) {
            size_t n = fread(out + total, 1, out_cap - 1 - total, p);
            if (n == 0) break;
            total += n;
        }
        out[total] = 0;
    }
    return pclose(p);
#elif defined(PLAT_WIN32)
    /* Use PowerShell for automation */
    char cmd[4096];
    snprintf(cmd, sizeof cmd, "powershell.exe -NoProfile -Command \"%s\"", script);
    FILE* p = _popen(cmd, "r");
    if (!p) return -1;
    if (out && out_cap > 0) {
        size_t total = 0;
        while (total < out_cap - 1) {
            size_t n = fread(out + total, 1, out_cap - 1 - total, p);
            if (n == 0) break;
            total += n;
        }
        out[total] = 0;
    }
    return _pclose(p);
#else
    (void)script; (void)out; (void)out_cap;
    return -1;
#endif
}

#endif /* PLATFORM_H */
