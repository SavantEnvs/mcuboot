/* Functional oracle for mayhem/test.sh: boots known flash images (committed fixtures made by
 * upstream's imgtool, see gen_fixtures.sh) through boot_go() and prints what MCUboot decided:
 * the return code, which image ends up in each slot (version from the header) and a hash of the
 * primary slot's payload (proves an encrypted upgrade was decrypted). test.sh diffs this against
 * a golden file. Usage: selftest <fixture dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sim_flash.h"

static uint32_t rd32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }

static void slot(const char *name, const uint8_t *s)
{
    if (rd32(s) != 0x96f3b83du) { printf(" %s=none", name); return; }
    uint16_t hsz = rd16(s + 8); uint32_t isz = rd32(s + 12);
    printf(" %s=%u.%u.%u+%u", name, s[20], s[21], rd16(s + 22), rd32(s + 24));
    if ((uint32_t)hsz + isz <= SIM_SLOT) {
        uint32_t h = 2166136261u;                       /* FNV-1a of the payload */
        for (uint32_t i = 0; i < isz; i++) { h ^= s[hsz + i]; h *= 16777619u; }
        printf("/%u/%08x", isz, h);
    }
}

static void run(const char *name, const uint8_t *data, size_t n)
{
    struct boot_rsp rsp;
    int rc = sim_run_boot_go(data, n, &rsp);
    printf("%s rc=%s", name, rc == 0 ? "ok" : "fail");
    if (rc == 0) printf(" off=0x%x", rsp.br_image_off);
    slot("primary", sim_flash);
    slot("secondary", sim_flash + SIM_SLOT);
    printf("\n");
}

int main(int argc, char **argv)
{
    static const char *cases[] = { "02_valid", "03_tampered", "04_upgrade", "05_bad_upgrade" };
    static uint8_t buf[SIM_FLASH_SZ];
    if (argc != 2) { fprintf(stderr, "usage: %s <fixture dir>\n", argv[0]); return 2; }
    run("01_empty", buf, 0);
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        char p[4096]; snprintf(p, sizeof p, "%s/%s.bin", argv[1], cases[i]);
        FILE *f = fopen(p, "rb");
        if (!f) { printf("%s missing\n", cases[i]); continue; }
        size_t n = fread(buf, 1, sizeof buf, f); fclose(f);
        run(cases[i], buf, n);
    }
    return 0;
}
