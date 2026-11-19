/* Functional oracle for the serial-recovery path: runs each committed boot_serial seed
 * (mayhem/boot_serial/testsuite: echo, image list, slot info, chunked upload, set pending/confirm,
 * reset; encrypted uploads) through the same driver as the fuzz target and prints every SMP response
 * MCUboot writes back (header + CBOR, hex), plus the start (header + first payload bytes) of each
 * slot afterwards — for an encrypted upload that shows the in-place decryption.
 * test.sh diffs this against expected_serial.txt. Usage: selftest_serial <seed dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "sim_flash.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern void (*serial_capture)(const char *s, int len);
static const char *cur;
static void cap(const char *s, int len)
{
    printf("%s tx", cur);
    for (int i = 0; i < len; i++) printf("%02x", (unsigned char)s[i]);
    printf("\n");
}

static int is_bin(const struct dirent *d)
{
    size_t n = strlen(d->d_name);
    return n > 4 && strcmp(d->d_name + n - 4, ".bin") == 0;
}

int main(int argc, char **argv)
{
    static uint8_t buf[1 << 18];
    struct dirent **ents;
    int ne;
    if (argc != 2) { fprintf(stderr, "usage: %s <seed dir>\n", argv[0]); return 2; }
    serial_capture = cap;
    ne = scandir(argv[1], &ents, is_bin, alphasort);     /* every seed, sorted by name */
    if (ne < 0) { perror(argv[1]); return 1; }
    for (int i = 0; i < ne; i++) {
        char p[4096]; snprintf(p, sizeof p, "%s/%s", argv[1], ents[i]->d_name);
        FILE *f = fopen(p, "rb");
        if (!f) { printf("%s missing\n", ents[i]->d_name); continue; }
        size_t n = fread(buf, 1, sizeof buf, f); fclose(f);
        cur = ents[i]->d_name;
        LLVMFuzzerTestOneInput(buf, n);
        printf("%s flash", cur);
        for (int s = 0; s < 2; s++) {           /* header + first payload bytes of each slot */
            const uint8_t *h = sim_flash + s * SIM_SLOT;
            printf(" ");
            for (int k = 0; k < 48; k++) printf("%02x", h[k]);
        }
        printf("\n");
        free(ents[i]);
    }
    free(ents);
    return 0;
}
