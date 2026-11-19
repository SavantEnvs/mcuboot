#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

# Functional oracle: mayhem/bin/selftest_<cfg> (built by build.sh with normal flags) feeds the
# committed fixtures in mayhem/<target>/testsuite to MCUboot and prints what it decided; each output
# line is diffed against mayhem/harness/expected_<cfg>.txt (one test per line):
#  - boot_go configs (imgtool-made flash images): boot verdict, image version left in each slot and a
#    hash of the primary payload — a valid image boots, a tampered one is rejected, a signed upgrade
#    is swapped/copied in (decrypted for the encrypted configs), a tampered upgrade is refused.
#  - boot_serial (SMP packet sequences): every response frame MCUboot sends back (echo, image list
#    with versions/hashes/flags, slot info, upload offsets, set-pending/confirm/reset results).
passed=0; failed=0
for cfg in ecdsa_scratch rsa_move_enc ed25519_overwrite_enc ecdsa_offset_enc boot_serial boot_serial_enc; do
  bin="$SRC/mayhem/bin/selftest_$cfg"
  exp="$SRC/mayhem/harness/expected_$cfg.txt"
  dir="$SRC/mayhem/boot_go_$cfg/testsuite"; case $cfg in boot_serial*) dir="$SRC/mayhem/$cfg/testsuite";; esac
  [ -x "$bin" ] || { echo "missing $bin (build.sh did not run?)" >&2; failed=$((failed + 1)); continue; }
  got=$("$bin" "$dir" 2>/dev/null) || true
  i=0
  while IFS= read -r want; do
    i=$((i + 1))
    line=$(printf '%s\n' "$got" | sed -n "${i}p")
    if [ "$line" = "$want" ]; then passed=$((passed + 1)); echo "PASS $cfg #$i ${want%% *}"
    else failed=$((failed + 1)); echo "FAIL $cfg #$i"; echo "  want: $want"; echo "  got:  $line"; fi
  done < "$exp"
  extra=$(printf '%s\n' "$got" | sed -n "$((i + 1)),\$p" | grep -c . || true)
  [ "$extra" -eq 0 ] || { failed=$((failed + 1)); echo "FAIL $cfg: $extra unexpected extra output line(s)"; }
done
emit_ctrf "mcuboot-selftest" "$passed" "$failed"
