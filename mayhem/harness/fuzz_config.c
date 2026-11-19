/*
 * fuzz_config: the YAML configuration (hev_socks5_tunnel_main_from_str).
 *
 * The config is parsed by the bundled libyaml and every section parser in
 * hev-config.c, then the loggers are initialized; the TUN fd passed is invalid
 * (EBADF), so tunnel init fails right after and the call returns.
 *
 * Precondition from the program's own contract: misc.pid-file daemonizes the
 * process (fork + exit), misc.log-file opens/creates an arbitrary path, and
 * misc.limit-nofile changes the process rlimit from its 65535 default. Those options act on the host, not
 * on the input, so inputs that set any of them are rejected. They are detected
 * with the program's own config parser (not by scanning bytes, which YAML escapes,
 * aliases and complex keys would defeat): parse once, read the three values back.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "hev-main.h"
#include "hev-config.h"

#define BAD_TUN_FD 0x3fffffff

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    if (size > 65536)
        return -1;
    if (hev_config_init_from_str (data, size) == 0) {
        const char *lf = hev_config_get_misc_log_file ();
        if (hev_config_get_misc_pid_file () ||
            hev_config_get_misc_limit_nofile () != 65535 ||
            (lf && strcmp (lf, "stdout") && strcmp (lf, "stderr")))
            return -1;
    }
    hev_socks5_tunnel_main_from_str (data, size, BAD_TUN_FD);
    return 0;
}
