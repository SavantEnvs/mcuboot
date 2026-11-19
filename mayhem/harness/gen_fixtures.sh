#!/usr/bin/env bash
# Regenerates the committed flash-image fixtures (mayhem/<target>/testsuite/*.bin) with upstream's
# own scripts/imgtool.py and the repo's test keys (whose public halves are compiled into
# sim/mcuboot-sys/csupport/keys.c). NOT run by build.sh — the outputs are committed so the build
# stays offline. Needs python3 with click, cryptography, cbor2, intelhex, pyyaml (e.g. via `uv run --with`).
# The primary-slot image is signed only (MCUboot never boots an encrypted primary); the upgrade in
# the secondary slot is also encrypted for the *_enc targets.
# Each fixture is a whole flash image: primary (64 KiB) | secondary (64 KiB) | scratch (8 KiB),
# with trailing erased (0xff) bytes stripped (the harness re-erases them).
set -euo pipefail
R=$(cd "$(dirname "$0")/../.." && pwd)
IT=${IMGTOOL:-"python3 $R/scripts/imgtool.py"}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
# deterministic payloads
python3 -c "import sys,hashlib;b=b''.join(hashlib.sha256(b'app1-%d'%i).digest() for i in range(94));open(sys.argv[1],'wb').write(b[:3000])" "$W/app1"
python3 -c "import sys,hashlib;b=b''.join(hashlib.sha256(b'app2-%d'%i).digest() for i in range(157));open(sys.argv[1],'wb').write(b[:5000])" "$W/app2"

gen() { # gen <target> "<sign args>" "<upgrade-only (encryption) args>"
  local t=$1 a=$2 e=$3 so=${4:-0}
  local out="$R/mayhem/$t/testsuite"; mkdir -p "$out"
  local c="-H 0x20 --pad-header --align 8 --slot-size 0x10000 --max-sectors 16"
  $IT sign $a $c -v 1.2.3+4 "$W/app1" "$W/v1"
  $IT sign $a $e $c -v 2.0.0+0 --pad "$W/app2" "$W/v2pad"
  python3 - "$W" "$out" "$so" <<'PY'
import sys
w, out, so = sys.argv[1], sys.argv[2], int(sys.argv[3])
SLOT, FLASH = 0x10000, 2*0x10000 + 0x2000
v1 = open(w+'/v1','rb').read(); v2 = open(w+'/v2pad','rb').read()
def flash(prim=b'', sec=b''):
    f = bytearray(b'\xff'*FLASH); f[:len(prim)] = prim; f[SLOT:SLOT+len(sec)] = sec
    if so and sec:   # image moved `so` bytes up, trailer (last sector) stays at the slot end
        body = sec[:SLOT-0x1000].rstrip(b'\xff')
        f[SLOT:2*SLOT-0x1000] = b'\xff'*(SLOT-0x1000); f[SLOT+so:SLOT+so+len(body)] = body
    return bytes(f).rstrip(b'\xff')
def flip(img, off):
    b = bytearray(img); b[off] ^= 0x01; return bytes(b)
cases = {
  '02_valid': flash(v1),
  '03_tampered': flash(flip(v1, 0x20 + 100)),
  '04_upgrade': flash(v1, v2),
  '05_bad_upgrade': flash(v1, flip(v2, 0x20 + 100)),
}
for k, v in cases.items():
    open('%s/%s.bin' % (out, k), 'wb').write(v)
PY
}
gen boot_go_ecdsa_scratch "-k $R/root-ec-p256.pem" ""
gen boot_go_rsa_move_enc "-k $R/root-rsa-2048.pem" "-E $R/enc-rsa2048-pub.pem"
gen boot_go_ed25519_overwrite_enc "-k $R/root-ed25519.pem --overwrite-only" "-E $R/enc-x25519-pub.pem"
# swap-using-offset stores the upgrade one sector into the secondary slot
gen boot_go_ecdsa_offset_enc "-k $R/root-ec-p256.pem -s 3" "-E $R/enc-ec256-pub.pem" 4096
