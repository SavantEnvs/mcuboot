/* Host flash backend for MCUboot's simulator C glue (sim/mcuboot-sys/csupport/run.c).
 * The Rust simulator normally provides these sim_* callbacks; here a flat RAM flash does.
 * Layout: primary slot (id 1) | secondary slot (id 2) | scratch (id 3), 4 KiB sectors. */
#ifndef MAYHEM_SIM_FLASH_H
#define MAYHEM_SIM_FLASH_H
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include "storage/flash_map.h"
#include "bootutil/bootutil.h"

/* Mirrors of the structs defined (not exported) in csupport/run.c. */
struct sim_context { int flash_counter; int jumped; uint8_t c_asserts; uint8_t c_catch_asserts; jmp_buf boot_jmpbuf; };
struct area { struct flash_area whole; struct flash_area *areas; uint32_t num_areas; uint8_t id; };
struct area_desc { struct area slots[16]; uint32_t num_slots; };
int invoke_boot_go(struct sim_context *ctx, struct area_desc *adesc, struct boot_rsp *rsp, int image_id);

#define SIM_SECT 4096u
#define SIM_SLOT (16u * SIM_SECT)
#define SIM_SCRATCH (2u * SIM_SECT)
#define SIM_FLASH_SZ (2u * SIM_SLOT + SIM_SCRATCH)
extern uint8_t sim_flash[SIM_FLASH_SZ];

/* Load `size` bytes at the start of flash (rest erased), run boot_go once.
 * Returns boot_go's rc; *rsp receives the boot response. */
int sim_run_boot_go(const uint8_t *data, size_t size, struct boot_rsp *rsp);
/* Install a fresh flash/area table/context without booting (for boot_serial), and drop it. */
void sim_flash_setup(const uint8_t *data, size_t size);
void sim_flash_teardown(void);
#endif
