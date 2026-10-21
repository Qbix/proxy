/* cosmo_compat.h — Linux API declarations for Cosmopolitan libc.
 *
 * cosmocc provides epoll, eventfd, sendfile, and accept4 in its
 * library but may not ship the sys/ headers that declare them.
 * This file supplies the missing declarations using the stable
 * Linux ABI definitions that Cosmopolitan is binary-compatible with.
 *
 * Included only when __COSMOPOLITAN__ is defined.
 */
#ifndef COSMO_COMPAT_H
#define COSMO_COMPAT_H

#ifdef __COSMOPOLITAN__

#include <stdint.h>
#include <sys/types.h>

/* ── epoll ──────────────────────────────────────────────────────────── */

#ifndef EPOLLIN
#define EPOLLIN      0x001
#define EPOLLPRI     0x002
#define EPOLLOUT     0x004
#define EPOLLERR     0x008
#define EPOLLHUP     0x010
#define EPOLLRDNORM  0x040
#define EPOLLRDBAND  0x080
#define EPOLLWRNORM  0x100
#define EPOLLWRBAND  0x200
#define EPOLLMSG     0x400
#define EPOLLRDHUP   0x2000
#define EPOLLONESHOT (1 << 30)
#define EPOLLET      (1u << 31)

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

#define EPOLL_CLOEXEC 0x80000

typedef union epoll_data {
    void    *ptr;
    int      fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t     events;
    epoll_data_t data;
} __attribute__((packed));

int epoll_create(int size);
int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
#endif /* EPOLLIN */

/* ── eventfd ────────────────────────────────────────────────────────── */

#ifndef EFD_SEMAPHORE
#define EFD_SEMAPHORE 1
#define EFD_CLOEXEC   0x80000
#define EFD_NONBLOCK  0x800

int eventfd(unsigned int initval, int flags);
typedef uint64_t eventfd_t;
int eventfd_read(int fd, eventfd_t *value);
int eventfd_write(int fd, eventfd_t value);
#endif /* EFD_SEMAPHORE */

/* ── sendfile ───────────────────────────────────────────────────────── */

#ifndef _SYS_SENDFILE_H
#define _SYS_SENDFILE_H
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
#endif

#endif /* __COSMOPOLITAN__ */
#endif /* COSMO_COMPAT_H */
