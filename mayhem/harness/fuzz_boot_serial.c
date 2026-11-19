/* Fuzz MCUboot's serial recovery (boot/boot_serial: MCUmgr/SMP image management over UART).
 * Entry: boot_serial_input(), the SMP packet handler upstream's own unit tests drive
 * (boot/boot_serial/test/src/boot_test.c: set boot_uf, call boot_serial_input per packet).
 * It reaches the SMP header checks, zcbor CBOR decoding/encoding, image list/set (image header,
 * TLV + hash parsing of what is in flash), slot info, echo, reset and image upload (flash writes).
 *
 * Input: [u32 LE n][n bytes: initial flash, primary|secondary|scratch][packets...]
 *        each packet = [u16 BE len][len bytes handed to boot_serial_input]
 *
 * State: boot_serial.c keeps the image-upload progress in function statics (bs_upload:
 * img_size/curr_off/img_num) with no reset API. Before each input the harness sends one fixed
 * upload packet with off=0 — upstream's own "restart upload" signal — so every input starts from
 * the same upload state. Flash, areas and context are rebuilt per input. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sim_flash.h"
#include "boot_serial/boot_serial.h"
#include "boot_serial_priv.h"

/* Responses are discarded while fuzzing; the selftest (selftest_serial.c) sets a capture hook. */
void (*serial_capture)(const char *s, int len);
static void uart_write(const char *s, int len) { if (serial_capture) serial_capture(s, len); }
static int uart_read(char *s, int len, int *nl) { (void)s; (void)len; *nl = 0; return 0; }
static const struct boot_uart_funcs uart = { .read = uart_read, .write = uart_write };

/* hal_system_reset() would reboot the MCU after a reset command; here it is a no-op. */
void hal_system_reset(void) { }
uint32_t os_uptime_get_ms_32(void) { return 0; }

static void send(const uint8_t *p, size_t n)
{
    char *b = malloc(n ? n : 1);           /* exact-size copy: overreads are caught by ASan */
    memcpy(b, p, n);
    boot_serial_input(b, (int)n);
    free(b);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* SMP write, group 1 (image), id 1 (upload): {"off":0,"len":1,"data":h''} */
    static const uint8_t reset_upload[] = {
        0x02, 0x00, 0x00, 0x11, 0x00, 0x01, 0x00, 0x01,
        0xa3, 0x63, 'o', 'f', 'f', 0x00, 0x63, 'l', 'e', 'n', 0x01, 0x64, 'd', 'a', 't', 'a', 0x40 };
    uint32_t n;
    if (size < 4) return -1;
    n = (uint32_t)data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16 | (uint32_t)data[3] << 24;
    data += 4; size -= 4;
    if (n > size) n = (uint32_t)size;
    /* restart the upload state on an erased flash (an off=0 upload erases the primary slot),
     * then lay the input's flash image down */
    sim_flash_setup(NULL, 0);
    boot_uf = &uart;
    send(reset_upload, sizeof reset_upload);
    memset(sim_flash, 0xff, sizeof sim_flash);
    memcpy(sim_flash, data, n < SIM_FLASH_SZ ? n : SIM_FLASH_SZ);
    data += n; size -= n;
    while (size >= 2) {
        size_t l = (size_t)data[0] << 8 | data[1];
        data += 2; size -= 2;
        if (l > size) l = size;
        send(data, l);
        data += l; size -= l;
    }
    sim_flash_teardown();              /* frees the area table; sim_flash keeps its contents */
    return 0;
}
