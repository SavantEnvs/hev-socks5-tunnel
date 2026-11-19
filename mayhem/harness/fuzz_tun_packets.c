/*
 * fuzz_tun_packets: raw IP packets arriving on the TUN device.
 *
 * Input: a sequence of [u16 big-endian length][packet bytes] records, each one IP
 * packet (v4 or v6) the kernel would hand the tunnel. Reaches lwIP ip4/ip6/icmp/
 * tcp/udp input and reassembly, the mapped-DNS responder (198.18.0.2:53), ICMP
 * echo reply, and TCP/UDP session creation + teardown. The SOCKS5 server port is a
 * bound but non-listening loopback socket, so every session's connect is refused
 * (the session error/teardown path) without any external process.
 */
#include "tunnel_driver.h"

static int placeholder_fd = -1;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
    int port;
    (void)argc;
    (void)argv;
    signal (SIGPIPE, SIG_IGN);
    placeholder_fd = td_bind_loopback (0, &port);
    td_make_config (port);
    return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    struct td_run r;
    size_t n;

    if (!td_split_ok (data, size))
        return -1;

    td_start (&r, td_cfg);
    n = td_queue_packets (r.sv[0], data, size);
    td_run_thread (&r);
    td_settle (&r, n, -1, NULL, 0);
    td_stop (&r);
    return 0;
}
