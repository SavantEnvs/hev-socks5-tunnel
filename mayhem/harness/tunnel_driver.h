/*
 * Shared driver for the in-process tunnel harnesses.
 *
 * Uses only the public library API (src/hev-main.h): hev_socks5_tunnel_main_from_str()
 * takes an external TUN fd, so a SOCK_DGRAM socketpair stands in for /dev/net/tun:
 * every datagram written to sv[0] is one IP packet the tunnel reads, every datagram
 * it writes back (ICMP echo replies, mapped-DNS answers, TCP RST/SYN-ACK/data, UDP
 * relay replies) shows up on sv[0].
 *
 * One tunnel instance per input: the tunnel runs in its own thread (main_from_str
 * blocks in the task loop), the harness thread feeds packets, optionally plays the
 * SOCKS5 server, then calls hev_socks5_tunnel_quit() and joins. Every per-tunnel
 * global (lwIP, sessions, mapped-DNS cache, stats, task system) is torn down by the
 * library on return, so no state carries across inputs. The only things kept are the
 * fixed config string and the listening/placeholder socket that fixes its port.
 */
#ifndef TUNNEL_DRIVER_H
#define TUNNEL_DRIVER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "hev-main.h"

#define TD_MTU 1500
#define TD_MAX_PACKETS 64
#define TD_MAX_CONNS 32

struct td_run {
    int sv[2];
    pthread_t thread;
    int ret;
    const char *cfg;
};

static char td_cfg[1024];

/* Fixed config. udp: 'tcp' so UDP sessions relay over the SOCKS5 TCP stream. */
static void
td_make_config (int port)
{
    snprintf (td_cfg, sizeof (td_cfg),
              "tunnel:\n"
              "  mtu: %d\n"
              "  ipv4: 198.18.0.1\n"
              "  ipv6: 'fc00::1'\n"
              "  icmp: 'reply'\n"
              "socks5:\n"
              "  port: %d\n"
              "  address: 127.0.0.1\n"
              "  udp: 'tcp'\n"
              "mapdns:\n"
              "  address: 198.18.0.2\n"
              "  port: 53\n"
              "  network: 100.64.0.0\n"
              "  netmask: 255.192.0.0\n"
              "  cache-size: 64\n"
              "misc:\n"
              "  connect-timeout: 200\n"
              "  tcp-read-write-timeout: 500\n"
              "  udp-read-write-timeout: 500\n"
              "  log-level: error\n"
              "  log-file: null\n",
              TD_MTU, port);
}

/* A loopback TCP socket bound to an ephemeral port; listening or not. */
static int
td_bind_loopback (int do_listen, int *port)
{
    struct sockaddr_in a;
    socklen_t l = sizeof (a);
    int fd = socket (AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        abort ();
    memset (&a, 0, sizeof (a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    if (bind (fd, (struct sockaddr *)&a, sizeof (a)) < 0)
        abort ();
    if (do_listen && listen (fd, 64) < 0)
        abort ();
    if (getsockname (fd, (struct sockaddr *)&a, &l) < 0)
        abort ();
    *port = ntohs (a.sin_port);
    if (do_listen)
        fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK);
    return fd;
}

static void *
td_thread (void *p)
{
    struct td_run *r = p;
    r->ret = hev_socks5_tunnel_main_from_str ((const unsigned char *)r->cfg,
                                              strlen (r->cfg), r->sv[1]);
    return NULL;
}

/*
 * Split the input into packets (each [u16 big-endian length][bytes]).
 *
 * Precondition (environment contract of the TUN fd the program is handed: a Linux
 * tun device with IFF_NO_PI, or Android VpnService's fd): every read returns one IP
 * packet built by the kernel network stack, so it is never shorter than the 20-byte
 * minimum IP header. The tunnel relies on that (it peeks data[9]/data[6] of every
 * packet before lwIP validates it). Inputs containing a shorter packet are rejected
 * (-1) rather than fed; zero-length records are skipped (a 0-byte read is not a
 * packet to the tunnel).
 */
#define TD_MIN_PACKET 20

static int
td_split_ok (const uint8_t *d, size_t n)
{
    size_t count = 0;
    while (n >= 2 && count < TD_MAX_PACKETS) {
        size_t len = ((size_t)d[0] << 8) | d[1];
        d += 2;
        n -= 2;
        if (len > n)
            len = n;
        if (len > TD_MTU)
            len = TD_MTU;
        if (len && len < TD_MIN_PACKET)
            return 0;
        if (len)
            count++;
        d += len;
        n -= len;
    }
    return 1;
}

/* Queue the packets into the TUN socketpair before the tunnel starts, so the
 * tunnel reads them in order. Returns the count. */
static size_t
td_queue_packets (int fd, const uint8_t *d, size_t n)
{
    size_t count = 0;
    while (n >= 2 && count < TD_MAX_PACKETS) {
        size_t len = ((size_t)d[0] << 8) | d[1];
        d += 2;
        n -= 2;
        if (len > n)
            len = n;
        if (len > TD_MTU)
            len = TD_MTU;
        if (len) {
            if (send (fd, d, len, 0) != (ssize_t)len)
                abort ();
            count++;
        }
        d += len;
        n -= len;
    }
    return count;
}

static void
td_start (struct td_run *r, const char *cfg)
{
    int buf = 1 << 20;
    if (socketpair (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, r->sv) < 0)
        abort ();
    setsockopt (r->sv[0], SOL_SOCKET, SO_SNDBUF, &buf, sizeof (buf));
    setsockopt (r->sv[1], SOL_SOCKET, SO_RCVBUF, &buf, sizeof (buf));
    setsockopt (r->sv[0], SOL_SOCKET, SO_RCVBUF, &buf, sizeof (buf));
    r->cfg = cfg;
    r->ret = 0;
}

static void
td_run_thread (struct td_run *r)
{
    if (pthread_create (&r->thread, NULL, td_thread, r) != 0)
        abort ();
}

static void
td_stop (struct td_run *r)
{
    hev_socks5_tunnel_quit ();
    pthread_join (r->thread, NULL);
    close (r->sv[0]);
    close (r->sv[1]);
}

/*
 * Let the tunnel consume the queued packets and answer them. Returns once every
 * queued packet has been read (tunnel tx counter) and the TUN side and the fake
 * server have been quiet for a few poll rounds. When srv_fd >= 0, accepted
 * connections get `reply` written once and are drained afterwards.
 */
static size_t
td_settle (struct td_run *r, size_t npkts, int srv_fd, const uint8_t *reply,
           size_t reply_len)
{
    struct pollfd p[2 + TD_MAX_CONNS];
    int conns[TD_MAX_CONNS];
    int nconns = 0, idle = 0, round;
    size_t replies = 0;
    uint8_t b[65536];

    for (round = 0; round < 800 && idle < 3; round++) {
        size_t tx = 0;
        int np = 0, i, ev, npolled = nconns;

        p[np].fd = r->sv[0];
        p[np++].events = POLLIN;
        if (srv_fd >= 0) {
            p[np].fd = srv_fd;
            p[np++].events = POLLIN;
        }
        for (i = 0; i < nconns; i++) {
            p[np].fd = conns[i];
            p[np++].events = POLLIN;
        }

        ev = poll (p, np, 5);
        hev_socks5_tunnel_stats (&tx, NULL, NULL, NULL);
        if (ev <= 0) {
            if (tx >= npkts)
                idle++;
            continue;
        }
        idle = 0;

        if (p[0].revents & POLLIN) {
            while (recv (r->sv[0], b, sizeof (b), MSG_DONTWAIT) >= 0)
                replies++;
        }
        if (srv_fd >= 0 && (p[1].revents & POLLIN)) {
            int c;
            while ((c = accept4 (srv_fd, NULL, NULL,
                                 SOCK_NONBLOCK | SOCK_CLOEXEC)) >= 0) {
                if (nconns == TD_MAX_CONNS) {
                    close (c);
                    continue;
                }
                if (reply_len)
                    (void)!send (c, reply, reply_len, MSG_NOSIGNAL);
                conns[nconns++] = c;
            }
        }
        for (i = 0; i < npolled; i++) {
            struct pollfd *q = &p[(srv_fd >= 0 ? 2 : 1) + i];
            if (!q->revents)
                continue;
            if (recv (conns[i], b, sizeof (b), MSG_DONTWAIT) == 0 ||
                (q->revents & (POLLERR | POLLHUP))) {
                close (conns[i]);
                conns[i] = -1;
            }
        }
        for (i = 0; i < nconns;) {
            if (conns[i] < 0)
                conns[i] = conns[--nconns];
            else
                i++;
        }
    }

    for (int i = 0; i < nconns; i++)
        close (conns[i]);
    return replies;
}

#endif
