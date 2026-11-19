#!/usr/bin/env bash
# mayhem/build.sh — build hev-socks5-tunnel's fuzz harnesses and its behavioral self-test.
#
# Upstream builds with plain GNU make (no configure); `make static` builds
# bin/libhev-socks5-tunnel.a (-DENABLE_LIBRARY, no main) plus the bundled third-part
# libraries (libyaml, lwIP, hev-task-system; git submodules) in place. CFLAGS given on
# the make command line reach the third-part sub-makes too, so the whole stack (lwIP's
# packet parsing included) is instrumented.
#
# The tree has one build layout (build/, bin/, third-part/*/{bin,build}), so the
# normal-flags self-test build runs first, its binary is stashed in mayhem/out/, then
# `make clean` and the sanitized fuzz build. Re-runnable: every run starts with a clean.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT"

# clang warns where upstream's gcc build does not; upstream builds with -Werror.
WARN="-Wno-error"
LIBS="bin/libhev-socks5-tunnel.a third-part/yaml/bin/libyaml.a third-part/lwip/bin/liblwip.a third-part/hev-task-system/bin/libhev-task-system.a"
INC="-Isrc -Isrc/misc -Isrc/core/include"

# 1) Self-test (test.sh's oracle), project's normal flags.
make clean >/dev/null
make -j"$MAYHEM_JOBS" static CC="$CC" CFLAGS="$WARN $COVERAGE_FLAGS"
$CC -O2 $COVERAGE_FLAGS $INC mayhem/tests/tunnel_selftest.c $LIBS -lpthread \
    -o "$OUT/tunnel_selftest"

# 2) Sanitized + coverage-instrumented library for the fuzzers.
#    lwIP alone is built first with UBSan's `null` check relaxed: its ip_2_ip6()/ip_2_ip4()
#    macros take &addr->member of a possibly-NULL address and NULL-check the result
#    afterwards (e.g. icmp6.c icmp6_send_response), which UBSan reports on every ICMPv6
#    error path. A real NULL dereference still faults and ASan reports the SEGV; the rest
#    of UBSan and ASan stay on and halting. The top-level make then finds lwIP up to date.
FUZZ_CFLAGS="$WARN $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
make clean >/dev/null
make -C third-part/lwip -j"$MAYHEM_JOBS" static CC="$CC" CFLAGS="$FUZZ_CFLAGS -fno-sanitize=null"
make -j"$MAYHEM_JOBS" static CC="$CC" CFLAGS="$FUZZ_CFLAGS"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o "$OUT/lsan_off.o"
for f in fuzz_tun_packets fuzz_socks5_reply fuzz_config; do
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $INC \
        "mayhem/harness/$f.c" "$OUT/lsan_off.o" $LIBS -lpthread -o "$SRC/$f"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC "$STANDALONE_FUZZ_MAIN" \
        "mayhem/harness/$f.c" "$OUT/lsan_off.o" $LIBS -lpthread -o "$SRC/$f-standalone"
done
