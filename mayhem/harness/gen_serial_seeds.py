#!/usr/bin/env python3
"""Seeds for the boot_serial target (format: see mayhem/harness/fuzz_boot_serial.c).
Built from the committed boot_go_ecdsa_scratch fixtures; needs cbor2. NOT run by build.sh."""
import os, struct, sys
import cbor2
R = os.path.dirname(os.path.abspath(__file__)) + '/..'
fx = R + '/boot_go_ecdsa_scratch/testsuite/'
out = R + '/boot_serial/testsuite/'
os.makedirs(out, exist_ok=True)

def smp(op, group, cid, payload, seq=0):
    body = cbor2.dumps(payload)
    return struct.pack('>BBHHBB', op, 0, len(body), group, seq, cid) + body

def pkts(*ps):
    return b''.join(struct.pack('>H', len(p)) + p for p in ps)

def seed(flash, *ps):
    return struct.pack('<I', len(flash)) + flash + pkts(*ps)

def sha_tlv(img):
    hsz, isz = struct.unpack_from('<HxxI', img, 8)
    off = hsz + isz
    magic, tot = struct.unpack_from('<HH', img, off)
    p, end = off + 4, off + tot
    while p < end:
        t, l = struct.unpack_from('<BxH', img, p)
        if t == 0x10:
            return img[p + 4:p + 4 + l]
        p += 4 + l
    raise SystemExit('no sha tlv')

READ, WRITE = 0, 2
valid = open(fx + '02_valid.bin', 'rb').read()
upg = open(fx + '04_upgrade.bin', 'rb').read()
v2 = upg[0x10000:0x10000 + 0x20 + 5000 + 0x200]
echo = smp(WRITE, 0, 0, {'d': 'hello'})
state = smp(READ, 1, 0, {})
slots = smp(READ, 1, 6, {})
reset = smp(WRITE, 0, 5, {})
open(out + 'list_valid.bin', 'wb').write(seed(valid, echo, state, slots))
chunks = [smp(WRITE, 1, 1, {'image': 0, 'off': 0, 'len': len(valid), 'data': valid[:400]})]
for o in range(400, len(valid), 400):
    chunks.append(smp(WRITE, 1, 1, {'off': o, 'data': valid[o:o + 400]}))
open(out + 'upload.bin', 'wb').write(seed(b'', *chunks, state))
h2 = sha_tlv(upg[0x10000:])
open(out + 'set_pending.bin', 'wb').write(
    seed(upg, state, smp(WRITE, 1, 0, {'hash': h2, 'confirm': False}), state, reset))
open(out + 'confirm.bin', 'wb').write(
    seed(valid, smp(WRITE, 1, 0, {'hash': sha_tlv(valid), 'confirm': True}), state))

# boot_serial_enc: uploads of an ECIES-P256 encrypted, ECDSA-signed image (the upgrade image of the
# boot_go_ecdsa_offset_enc fixtures) into the primary slot, which MCUboot decrypts in place.
out = R + '/boot_serial_enc/testsuite/'
os.makedirs(out, exist_ok=True)
fo = open(R + '/boot_go_ecdsa_offset_enc/testsuite/04_upgrade.bin', 'rb').read()
enc = fo[0x10000 + 0x1000:]
hsz, isz = struct.unpack_from('<HxxI', enc, 8)
tot = struct.unpack_from('<HH', enc, hsz + isz)[1]
if struct.unpack_from('<H', enc, hsz + isz)[0] == 0x6908:      # protected TLVs first
    tot2 = struct.unpack_from('<HH', enc, hsz + isz + tot)[1]
    tot += tot2
enc = enc[:hsz + isz + tot]
def upload(img, step):
    c = [smp(WRITE, 1, 1, {'image': 0, 'off': 0, 'len': len(img), 'data': img[:step]})]
    for o in range(step, len(img), step):
        c.append(smp(WRITE, 1, 1, {'off': o, 'data': img[o:o + step]}))
    return c
open(out + 'upload_enc.bin', 'wb').write(seed(b'', *upload(enc, 512), state))
open(out + 'upload_enc_over_valid.bin', 'wb').write(seed(valid, *upload(enc, 1024), state, slots))
open(out + 'upload_plain.bin', 'wb').write(seed(b'', *upload(valid, 512), state))
