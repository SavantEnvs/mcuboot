/* Fuzz MCUboot's boot_go() (via the simulator's invoke_boot_go) on attacker-controlled flash:
 * the input is the raw contents of primary slot | secondary slot | scratch (rest erased 0xff).
 * Reaches image header/TLV parsing, hash + signature validation, (encrypted-image key TLVs),
 * swap/trailer state parsing and the upgrade copy logic of the compiled-in configuration. */
#include "sim_flash.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct boot_rsp rsp;
    (void)sim_run_boot_go(data, size, &rsp);
    return 0;
}
