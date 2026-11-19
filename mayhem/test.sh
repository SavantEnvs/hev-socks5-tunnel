#!/usr/bin/env bash
# mayhem/test.sh — RUN the behavioral self-test built by mayhem/build.sh.
#
# Upstream's own suite (tests/run.sh) needs root, network namespaces and /dev/net/tun,
# none of which exist in the commit image, so the oracle is mayhem/tests/tunnel_selftest.c:
# it drives the library through its public API (main_from_str + an external TUN fd) with
# known packets and asserts the packets that come back (mapped-DNS answers and caching,
# ICMP echo reply, TCP SYN-ACK) and config rejection. Each check prints PASS/FAIL.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/mayhem/out/tunnel_selftest"
EXPECTED=7
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing — mayhem/build.sh did not build it" >&2
  emit_ctrf tunnel-selftest 0 "$EXPECTED"
  exit 1
fi

out="$("$RUNNER" 2>&1)"; rc=$?
echo "$out"
passed=$(grep -c '^PASS ' <<<"$out")
failed=$(grep -c '^FAIL ' <<<"$out")
# A check that never reported (crash, early exit) counts as failed.
missing=$(( EXPECTED - passed - failed ))
[ "$missing" -gt 0 ] && failed=$(( failed + missing ))
[ "$rc" -ne 0 ] && [ "$failed" -eq 0 ] && failed=1
emit_ctrf tunnel-selftest "$passed" "$failed"
