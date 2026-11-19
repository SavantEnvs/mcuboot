#!/usr/bin/env bash
#
# mayhem/build.sh — build MCUboot's bootutil for the host and the boot_go fuzz harnesses.
#
# MCUboot has no host build of its own besides the Rust simulator; sim/mcuboot-sys/build.rs lists,
# per feature, the -D defines and C sources it compiles. This script follows that recipe with clang
# directly (the Rust side is replaced by mayhem/harness/sim_flash.c, a flat RAM flash backend).
# Everything is #ifdef-selected, so each target is one configuration (signature scheme, key-wrap
# scheme, upgrade strategy) that compiles different parsers.
#
# The only submodule needed, ext/mbedtls-3.6.0, is baked into the image by mayhem/Dockerfile at
# /opt/toolchains/deps/mbedtls-3.6.0/src (pinned to the submodule commit); nothing is fetched here.
#
# Outputs (gitignored, mayhem/.gitignore):
#   mayhem/bin/fuzz_<target>             libFuzzer harness (ASan+UBSan, DWARF 3)
#   mayhem/bin/fuzz_<target>-standalone  run-once reproducer
#   mayhem/bin/selftest_<cfg>         functional oracle (normal flags) that test.sh runs
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${MBEDTLS_DIR:=/opt/toolchains/deps/mbedtls-3.6.0/src}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
[ -f "$MBEDTLS_DIR/library/asn1parse.c" ] || { echo "mbedtls sources missing at $MBEDTLS_DIR" >&2; exit 1; }

OUT=mayhem/bin; OBJ=mayhem/obj
mkdir -p "$OUT" "$OBJ"

B=boot/bootutil/src; CS=sim/mcuboot-sys/csupport; T=ext/tinycrypt/lib/source; M=$MBEDTLS_DIR/library
COMMON_DEFS="-D__BOOTSIM__ -DMCUBOOT_HAVE_LOGGING -DMCUBOOT_USE_FLASH_AREA_GET_SECTORS -DMCUBOOT_HAVE_ASSERT_H
  -DMCUBOOT_MAX_IMG_SECTORS=128 -DMCUBOOT_BOOT_MAX_ALIGN=8 -DMCUBOOT_IMAGE_NUMBER=1 -DMCUBOOT_VALIDATE_PRIMARY_SLOT"
INCS="-Iboot/bootutil/include -I$CS -Iext/tinycrypt/lib/include -Iext/tinycrypt-sha512/lib/include
  -I$MBEDTLS_DIR/include -Imayhem/harness"
BOOTUTIL="$B/image_validate.c $B/bootutil_find_key.c $B/bootutil_img_hash.c $B/bootutil_img_security_cnt.c
  $B/loader.c $B/swap_misc.c $B/swap_scratch.c $B/swap_move.c $B/swap_offset.c $B/caps.c $B/bootutil_misc.c
  $B/bootutil_area.c $B/bootutil_loader.c $B/bootutil_public.c $B/tlv.c $B/fault_injection_hardening.c
  $CS/run.c $CS/keys.c mayhem/harness/sim_flash.c"

# compile <objdir> <cflags> <extra cflags for vendored tinycrypt> <sources...> — compiles every source (always: a header edit must not
# leave a stale object) and prints the object list
compile() {
  local dir=$1 flags=$2 relax=$3; shift 3
  mkdir -p "$dir"
  printf '%s\n' "$@" | xargs -P "$MAYHEM_JOBS" -I{} sh -c '
    s={}; o="$0/$(echo "$s" | tr / _ | sed "s/^_*//").o"
    x=; case "$s" in ext/tinycrypt/*) x=$2;; esac
    $CC -std=gnu99 $1 $x -c "$s" -o "$o"' "$dir" "$flags" "$relax" || return 1
  for s in "$@"; do echo "$dir/$(echo "$s" | tr / _ | sed 's/^_*//').o"; done
}

# Vendored tinycrypt builds AES round keys / SHA words with `(uint8_t)x << 24` on int, which UBSan's
# shift-base check reports for every key byte >= 0x80 (benign: the result is stored into a uint32_t).
# It fires on every encrypted image, so only that one check is relaxed, only for ext/tinycrypt/*;
# ASan and all other UBSan checks stay halting. Empty when the sanitizers are switched off.
TINYCRYPT_RELAX=
case "$SANITIZER_FLAGS" in *undefined*|*shift*) TINYCRYPT_RELAX="-fno-sanitize=shift-base";; esac

# build_cfg <target> <harness.c> <selftest main .c> "<defines>" <extra sources...>
build_cfg() {
  local name=$1 harness=$2 st=$3 defs=$4; shift 4
  local srcs="$BOOTUTIL $*"
  local fz="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 $COMMON_DEFS $defs $INCS"
  local nm="-O1 $COVERAGE_FLAGS $COMMON_DEFS $defs $INCS"
  local fobjs nobjs
  # shellcheck disable=SC2086
  fobjs=$(compile "$OBJ/$name/fuzz" "$fz" "$TINYCRYPT_RELAX" $srcs "$harness")
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $fobjs "$OBJ/lsan_off.o" -o "$OUT/fuzz_$name"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OBJ/standalone_main.o" $fobjs "$OBJ/lsan_off.o" -o "$OUT/fuzz_$name-standalone"
  # the functional oracle (normal flags) that test.sh runs
  # shellcheck disable=SC2086
  nobjs=$(compile "$OBJ/$name/plain" "$nm" "" $srcs $st)
  # shellcheck disable=SC2086
  $CC $COVERAGE_FLAGS $nobjs -o "$OUT/selftest_${name#boot_go_}"
}

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OBJ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"

# 1) ECDSA-P256 (tinycrypt) signatures, swap using scratch.
build_cfg boot_go_ecdsa_scratch mayhem/harness/fuzz_boot_go.c mayhem/harness/selftest.c \
  "-DMCUBOOT_SIGN_EC256 -DMCUBOOT_USE_TINYCRYPT -DCONFIG_BOOT_SWAP_USING_SCRATCH -DMCUBOOT_SWAP_USING_SCRATCH -DMBEDTLS_CONFIG_FILE=<config-asn1.h>" \
  $B/image_ecdsa.c $T/utils.c $T/sha256.c $T/ecc.c $T/ecc_dsa.c $T/ecc_platform_specific.c \
  $M/platform_util.c $M/asn1parse.c $M/platform.c

# 2) RSA-2048 PSS signatures + RSA-OAEP encrypted images (mbedTLS), swap using move.
build_cfg boot_go_rsa_move_enc mayhem/harness/fuzz_boot_go.c mayhem/harness/selftest.c \
  "-DMCUBOOT_SIGN_RSA -DMCUBOOT_SIGN_RSA_LEN=2048 -DCONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN=2048 -DMCUBOOT_USE_MBED_TLS -DMCUBOOT_SWAP_USING_MOVE -DMCUBOOT_ENCRYPT_RSA -DMCUBOOT_ENC_IMAGES -I$M -DMBEDTLS_CONFIG_FILE=<config-rsa.h>" \
  $B/image_rsa.c $B/encrypted.c \
  $M/sha256.c $M/platform.c $M/platform_util.c $M/rsa.c $M/rsa_alt_helpers.c $M/md.c $M/aes.c \
  $M/bignum.c $M/bignum_core.c $M/constant_time.c $M/nist_kw.c $M/asn1parse.c $M/asn1write.c

# 3) Ed25519 signatures + X25519 (ECIES) encrypted images, overwrite-only with downgrade prevention.
build_cfg boot_go_ed25519_overwrite_enc mayhem/harness/fuzz_boot_go.c mayhem/harness/selftest.c \
  "-DMCUBOOT_SIGN_ED25519 -DMCUBOOT_USE_TINYCRYPT -DMCUBOOT_OVERWRITE_ONLY -DMCUBOOT_DOWNGRADE_PREVENTION -DMCUBOOT_ENCRYPT_X25519 -DMCUBOOT_ENC_IMAGES -DMCUBOOT_SWAP_SAVE_ENCTLV -DMBEDTLS_CONFIG_FILE=<config-asn1.h>" \
  $B/image_ed25519.c $B/encrypted.c ext/tinycrypt-sha512/lib/source/sha512.c ext/fiat/src/curve25519.c \
  $T/utils.c $T/sha256.c $T/aes_encrypt.c $T/aes_decrypt.c $T/ctr_mode.c $T/hmac.c \
  $M/platform_util.c $M/asn1parse.c $M/platform.c

# 4) ECDSA-P256 signatures + ECIES-P256 encrypted images (tinycrypt), swap using offset,
#    hardware rollback protection (security-counter TLV vs. an NV counter).
build_cfg boot_go_ecdsa_offset_enc mayhem/harness/fuzz_boot_go.c mayhem/harness/selftest.c \
  "-DMCUBOOT_SIGN_EC256 -DMCUBOOT_USE_TINYCRYPT -DMCUBOOT_SWAP_USING_OFFSET -DMCUBOOT_ENCRYPT_EC256 -DMCUBOOT_ENC_IMAGES -DMCUBOOT_SWAP_SAVE_ENCTLV -DMCUBOOT_HW_ROLLBACK_PROT -DMBEDTLS_CONFIG_FILE=<config-asn1.h>" \
  $B/image_ecdsa.c $B/encrypted.c $CS/security_cnt.c $T/utils.c $T/sha256.c $T/ecc.c $T/ecc_dsa.c $T/ecc_dh.c \
  $T/ecc_platform_specific.c $T/aes_encrypt.c $T/aes_decrypt.c $T/ctr_mode.c $T/hmac.c \
  $M/platform_util.c $M/asn1parse.c $M/platform.c

# 5) Serial recovery (MCUmgr/SMP over UART, raw SMP framing) on top of config 1: boot_serial.c +
#    zcbor; mynewt-port headers it includes are stubbed in mayhem/harness/serial_shim.
#    zcbor_bulk.c calls every typed zcbor decoder (e.g. zcbor_size_decode(state, size_t *)) through
#    a generic bool(*)(zcbor_state_t *, void *) pointer — UBSan's `function` check aborts on every
#    CBOR map decode (benign on all supported ABIs), so that one check is off for this target.
build_cfg boot_serial mayhem/harness/fuzz_boot_serial.c "mayhem/harness/fuzz_boot_serial.c mayhem/harness/selftest_serial.c" \
  "-DMCUBOOT_SIGN_EC256 -DMCUBOOT_USE_TINYCRYPT -DCONFIG_BOOT_SWAP_USING_SCRATCH -DMCUBOOT_SWAP_USING_SCRATCH -DMBEDTLS_CONFIG_FILE=<config-asn1.h>
   -DMCUBOOT_SERIAL_RAW_PROTOCOL -DMCUBOOT_SERIAL_IMG_GRP_HASH -DMCUBOOT_SERIAL_IMG_GRP_SLOT_INFO -DMCUBOOT_SERIAL_IMG_GRP_IMAGE_STATE
   -DMCUBOOT_BOOT_MGMT_ECHO -DMCUBOOT_PERUSER_MGMT_GROUP_ENABLED=0 -fno-sanitize=function
   -Imayhem/harness/serial_shim -Iboot/boot_serial/include -Iboot/boot_serial/src -Iboot/zcbor/include -Iboot/bootutil/src" \
  $B/image_ecdsa.c $T/utils.c $T/sha256.c $T/ecc.c $T/ecc_dsa.c $T/ecc_platform_specific.c \
  $M/platform_util.c $M/asn1parse.c $M/platform.c \
  boot/boot_serial/src/boot_serial.c boot/boot_serial/src/zcbor_bulk.c \
  boot/zcbor/src/zcbor_common.c boot/zcbor/src/zcbor_decode.c boot/zcbor/src/zcbor_encode.c

# 6) Serial recovery with encrypted-image support (ECIES-P256, tinycrypt): an uploaded encrypted
#    image is validated and decrypted in place (boot_serial_encryption.c).
build_cfg boot_serial_enc mayhem/harness/fuzz_boot_serial.c "mayhem/harness/fuzz_boot_serial.c mayhem/harness/selftest_serial.c" \
  "-DMCUBOOT_SIGN_EC256 -DMCUBOOT_USE_TINYCRYPT -DCONFIG_BOOT_SWAP_USING_SCRATCH -DMCUBOOT_SWAP_USING_SCRATCH -DMBEDTLS_CONFIG_FILE=<config-asn1.h>
   -DMCUBOOT_ENCRYPT_EC256 -DMCUBOOT_ENC_IMAGES -DMCUBOOT_SWAP_SAVE_ENCTLV
   -DMCUBOOT_SERIAL_RAW_PROTOCOL -DMCUBOOT_SERIAL_IMG_GRP_HASH -DMCUBOOT_SERIAL_IMG_GRP_SLOT_INFO -DMCUBOOT_SERIAL_IMG_GRP_IMAGE_STATE
   -DMCUBOOT_BOOT_MGMT_ECHO -DMCUBOOT_PERUSER_MGMT_GROUP_ENABLED=0 -fno-sanitize=function
   -Imayhem/harness/serial_shim -Iboot/boot_serial/include -Iboot/boot_serial/src -Iboot/zcbor/include -Iboot/bootutil/src" \
  $B/image_ecdsa.c $B/encrypted.c $T/utils.c $T/sha256.c $T/ecc.c $T/ecc_dsa.c $T/ecc_dh.c \
  $T/ecc_platform_specific.c $T/aes_encrypt.c $T/aes_decrypt.c $T/ctr_mode.c $T/hmac.c \
  $M/platform_util.c $M/asn1parse.c $M/platform.c \
  boot/boot_serial/src/boot_serial.c boot/boot_serial/src/boot_serial_encryption.c boot/boot_serial/src/zcbor_bulk.c \
  boot/zcbor/src/zcbor_common.c boot/zcbor/src/zcbor_decode.c boot/zcbor/src/zcbor_encode.c

ls -l "$OUT"
