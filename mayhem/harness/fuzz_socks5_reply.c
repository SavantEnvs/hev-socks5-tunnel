/*
 * fuzz_socks5_reply: TUN packets + the bytes the SOCKS5 server sends back.
 *
 * Input: [u16 big-endian length L][L bytes of TUN packet records, as in
 * fuzz_tun_packets][rest = server byte stream]. The harness listens on a loopback
 * port configured as the SOCKS5 server (udp: 'tcp', so UDP sessions use the
 * UDP-in-TCP relay); each connection the tunnel opens is answered with the server
 * byte stream: method selection / auth, CONNECT or UDP ASSOCIATE reply with its
 * bound address, then relayed TCP data or UDP-in-TCP datagrams (address type,
 * address, length) that hev-socks5-core parses and the tunnel splices back into
 * lwIP / coalesces into UDP datagrams to the TUN device.
 */
#include "tunnel_driver.h"

static int listen_fd = -1;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
    int port;
    (void)argc;
    (void)argv;
    signal (SIGPIPE, SIG_IGN);
    listen_fd = td_bind_loopback (1, &port);
    td_make_config (port);
    return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    struct td_run r;
    size_t plen, n;

    if (size < 2)
        return -1;
    plen = ((size_t)data[0] << 8) | data[1];
    data += 2;
    size -= 2;
    if (plen > size)
        plen = size;

    if (!td_split_ok (data, plen))
        return -1;

    td_start (&r, td_cfg);
    n = td_queue_packets (r.sv[0], data, plen);
    td_run_thread (&r);
    td_settle (&r, n, listen_fd, data + plen, size - plen);
    td_stop (&r);
    return 0;
}
