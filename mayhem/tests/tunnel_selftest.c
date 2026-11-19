/*
 * Behavioral self-test of the tunnel through its public library API
 * (hev_socks5_tunnel_main_from_str with an external TUN fd). Known packets in,
 * known packets out; prints "PASS <name>" / "FAIL <name>" per check for test.sh.
 * Built with the project's normal flags (no sanitizers) by mayhem/build.sh.
 */
#include "../harness/tunnel_driver.h"

static int failures;

static void
check (int ok, const char *name)
{
    printf ("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static size_t
ip4_udp (uint8_t *p, const uint8_t src[4], const uint8_t dst[4], int sport,
         int dport, const uint8_t *pl, size_t n)
{
    size_t tot = 20 + 8 + n;
    memset (p, 0, 28);
    p[0] = 0x45;
    p[2] = tot >> 8;
    p[3] = tot;
    p[8] = 64;
    p[9] = 17;
    memcpy (p + 12, src, 4);
    memcpy (p + 16, dst, 4);
    p[20] = sport >> 8;
    p[21] = sport;
    p[22] = dport >> 8;
    p[23] = dport;
    p[24] = (8 + n) >> 8;
    p[25] = 8 + n;
    memcpy (p + 28, pl, n);
    return tot;
}

static size_t
dns_query (uint8_t *q, uint16_t id, const char *label)
{
    size_t n = 0, l = strlen (label);
    q[n++] = id >> 8;
    q[n++] = id;
    q[n++] = 1; /* RD */
    q[n++] = 0;
    q[n++] = 0;
    q[n++] = 1; /* QDCOUNT */
    memset (q + n, 0, 6);
    n += 6;
    q[n++] = l;
    memcpy (q + n, label, l);
    n += l;
    q[n++] = 3;
    memcpy (q + n, "com", 3);
    n += 3;
    q[n++] = 0;
    q[n++] = 0;
    q[n++] = 1; /* A */
    q[n++] = 0;
    q[n++] = 1; /* IN */
    return n;
}

/* Start a tunnel, send the packets, collect up to `max` reply datagrams. */
static int
roundtrip (uint8_t pkts[][256], size_t *lens, int npk, uint8_t out[][2048],
           ssize_t *olens, int max)
{
    struct td_run r;
    int got = 0, i;
    td_start (&r, td_cfg);
    for (i = 0; i < npk; i++)
        send (r.sv[0], pkts[i], lens[i], 0);
    td_run_thread (&r);
    for (i = 0; i < 300 && got < max; i++) {
        struct pollfd p = { r.sv[0], POLLIN, 0 };
        if (poll (&p, 1, 10) > 0) {
            olens[got] = recv (r.sv[0], out[got], 2048, 0);
            if (olens[got] > 0)
                got++;
        }
    }
    td_stop (&r);
    return got;
}

static const uint8_t client[4] = { 198, 18, 0, 1 };
static const uint8_t mapdns[4] = { 198, 18, 0, 2 };

static int
dns_answer (const uint8_t *b, ssize_t n, uint16_t id, uint8_t ip[4])
{
    const uint8_t *d = b + 28;
    if (n < 28 + 12 + 4 || (b[0] >> 4) != 4 || b[9] != 17)
        return 0;
    if (memcmp (b + 12, mapdns, 4) || memcmp (b + 16, client, 4))
        return 0;
    if (((b[20] << 8) | b[21]) != 53 || ((b[22] << 8) | b[23]) != 40000)
        return 0;
    if (((d[0] << 8) | d[1]) != id || !(d[2] & 0x80) || ((d[6] << 8) | d[7]) != 1)
        return 0;
    memcpy (ip, b + n - 4, 4);
    return 1;
}

int
main (void)
{
    static uint8_t pk[4][256], out[8][2048];
    size_t lens[4];
    ssize_t olens[8];
    uint8_t q[128], ip1[4] = { 0 }, ip2[4] = { 0 }, ip3[4] = { 0 };
    int port, got, n;
    int ph = td_bind_loopback (0, &port);

    signal (SIGPIPE, SIG_IGN);
    td_make_config (port);
    setvbuf (stdout, NULL, _IONBF, 0);

    /* 1. Mapped DNS: two names get two distinct addresses from 100.64.0.0/10,
     *    the same name asked twice gets the same address. */
    n = dns_query (q, 0x1111, "alpha");
    lens[0] = ip4_udp (pk[0], client, mapdns, 40000, 53, q, n);
    n = dns_query (q, 0x2222, "bravo");
    lens[1] = ip4_udp (pk[1], client, mapdns, 40000, 53, q, n);
    n = dns_query (q, 0x3333, "alpha");
    lens[2] = ip4_udp (pk[2], client, mapdns, 40000, 53, q, n);
    got = roundtrip (pk, lens, 3, out, olens, 3);
    check (got == 3, "mapdns_three_replies");
    check (got >= 1 && dns_answer (out[0], olens[0], 0x1111, ip1) &&
               ip1[0] == 100 && (ip1[1] & 0xc0) == 64,
           "mapdns_answer_in_mapped_network");
    check (got >= 2 && dns_answer (out[1], olens[1], 0x2222, ip2) &&
               memcmp (ip1, ip2, 4) != 0 && ip2[0] == 100,
           "mapdns_distinct_names_distinct_addrs");
    check (got >= 3 && dns_answer (out[2], olens[2], 0x3333, ip3) &&
               memcmp (ip1, ip3, 4) == 0,
           "mapdns_same_name_cached_addr");

    /* 2. ICMP echo (icmp: reply): an echo request to any address is answered
     *    with an echo reply, addresses swapped, id/seq/payload preserved. */
    {
        static const uint8_t dst[4] = { 203, 0, 113, 7 };
        uint8_t *p = pk[0];
        memset (p, 0, 64);
        p[0] = 0x45;
        p[3] = 20 + 8 + 16;
        p[8] = 64;
        p[9] = 1;
        memcpy (p + 12, client, 4);
        memcpy (p + 16, dst, 4);
        p[20] = 8; /* echo request */
        p[24] = 0xbe;
        p[25] = 0xef;
        p[27] = 7;
        memcpy (p + 28, "hev-socks5-test!", 16);
        lens[0] = 44;
        got = roundtrip (pk, lens, 1, out, olens, 1);
        check (got == 1 && olens[0] == 44 && out[0][9] == 1 && out[0][20] == 0 &&
                   !memcmp (out[0] + 12, dst, 4) &&
                   !memcmp (out[0] + 16, client, 4) && out[0][24] == 0xbe &&
                   out[0][25] == 0xef && out[0][27] == 7 &&
                   !memcmp (out[0] + 28, "hev-socks5-test!", 16),
               "icmp_echo_reply");
    }

    /* 3. TCP: a SYN is accepted by the stack (SYN-ACK back to the client with
     *    the ports swapped and ack = seq + 1) before the SOCKS5 connect fails. */
    {
        static const uint8_t dst[4] = { 203, 0, 113, 9 };
        uint8_t *p = pk[0];
        memset (p, 0, 64);
        p[0] = 0x45;
        p[3] = 40;
        p[8] = 64;
        p[9] = 6;
        memcpy (p + 12, client, 4);
        memcpy (p + 16, dst, 4);
        p[20] = 0x9c; p[21] = 0x40; /* 40000 */
        p[22] = 0; p[23] = 80;
        p[24] = 0x10; p[25] = 0x20; p[26] = 0x30; p[27] = 0x40; /* seq */
        p[32] = 0x50;
        p[33] = 0x02; /* SYN */
        p[34] = 0xff; p[35] = 0xff;
        lens[0] = 40;
        got = roundtrip (pk, lens, 1, out, olens, 1);
        check (got >= 1 && olens[0] >= 40 && out[0][9] == 6 &&
                   !memcmp (out[0] + 12, dst, 4) &&
                   ((out[0][20] << 8) | out[0][21]) == 80 &&
                   ((out[0][22] << 8) | out[0][23]) == 40000 &&
                   (out[0][33] & 0x12) == 0x12 && out[0][28] == 0x10 &&
                   out[0][29] == 0x20 && out[0][30] == 0x30 && out[0][31] == 0x41,
               "tcp_syn_ack");
    }

    /* 4. Config: malformed YAML and a config without a socks5 section fail. */
    check (hev_socks5_tunnel_main_from_str ((const unsigned char *)"tunnel: [", 9,
                                            0x3fffffff) == -1,
           "config_bad_yaml_rejected");
    check (hev_socks5_tunnel_main_from_str ((const unsigned char *)"tunnel:\n  mtu: 1500\n",
                                            20, 0x3fffffff) == -1,
           "config_missing_socks5_rejected");

    close (ph);
    printf ("SUMMARY failures=%d\n", failures);
    return failures ? 1 : 0;
}
