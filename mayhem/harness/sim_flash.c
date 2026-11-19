/* See sim_flash.h. Every call of sim_run_boot_go() starts from a freshly erased flash and a
 * fresh area/context set, so each input's result depends only on that input. */
#include <stdlib.h>
#include <string.h>
#include "sim_flash.h"

uint8_t sim_flash[SIM_FLASH_SZ];
static struct area_desc *g_areas;
static struct sim_context *g_ctx;

struct area_desc *sim_get_flash_areas(void) { return g_areas; }
void sim_set_flash_areas(struct area_desc *a) { g_areas = a; }
void sim_reset_flash_areas(void) { g_areas = NULL; }
struct sim_context *sim_get_context(void) { return g_ctx; }
void sim_set_context(struct sim_context *c) { g_ctx = c; }
void sim_reset_context(void) { g_ctx = NULL; }
int sim_log_enabled(int level) { (void)level; return 0; }
uint32_t sim_flash_align(uint8_t id) { (void)id; return 8; }
uint8_t sim_flash_erased_val(uint8_t id) { (void)id; return 0xff; }

static int oob(uint32_t off, uint32_t sz) { return off > SIM_FLASH_SZ || sz > SIM_FLASH_SZ - off; }
int sim_flash_erase(uint8_t id, uint32_t off, uint32_t sz)
{ (void)id; if (oob(off, sz)) return -1; memset(sim_flash + off, 0xff, sz); return 0; }
int sim_flash_read(uint8_t id, uint32_t off, uint8_t *d, uint32_t sz)
{ (void)id; if (oob(off, sz)) return -1; memcpy(d, sim_flash + off, sz); return 0; }
int sim_flash_write(uint8_t id, uint32_t off, const uint8_t *s, uint32_t sz)
{
    (void)id;
    if (oob(off, sz)) return -1;
    for (uint32_t i = 0; i < sz; i++) sim_flash[off + i] &= s[i];   /* NOR semantics */
    return 0;
}

static void mk(struct area *a, uint8_t id, uint32_t off, uint32_t size)
{
    uint32_t n = size / SIM_SECT;
    a->whole.fa_id = id; a->whole.fa_device_id = 0; a->whole.fa_off = off; a->whole.fa_size = size;
    a->areas = calloc(n, sizeof(*a->areas)); a->num_areas = n; a->id = id;
    for (uint32_t i = 0; i < n; i++) {
        a->areas[i].fa_id = id; a->areas[i].fa_device_id = 0;
        a->areas[i].fa_off = off + i * SIM_SECT; a->areas[i].fa_size = SIM_SECT;
    }
}

/* Fresh flash (data at its start, rest erased) + area table + sim context, installed for the
 * flash_area_* backend in csupport/run.c. */
static struct area_desc g_ad;
static struct sim_context g_sctx;
static uint32_t g_nv_counter;

void sim_flash_setup(const uint8_t *data, size_t size)
{
    memset(&g_ad, 0, sizeof g_ad); memset(&g_sctx, 0, sizeof g_sctx);
    g_nv_counter = 0;
    memset(sim_flash, 0xff, sizeof sim_flash);
    if (size > SIM_FLASH_SZ) size = SIM_FLASH_SZ;
    if (size) memcpy(sim_flash, data, size);
    mk(&g_ad.slots[0], 1, 0, SIM_SLOT);
    mk(&g_ad.slots[1], 2, SIM_SLOT, SIM_SLOT);
    mk(&g_ad.slots[2], 3, 2 * SIM_SLOT, SIM_SCRATCH);
    g_ad.num_slots = 3;
    /* c_catch_asserts = 0: a failed bootutil ASSERT aborts, so Mayhem reports it. */
    g_sctx.c_catch_asserts = 0;
    sim_set_flash_areas(&g_ad);
    sim_set_context(&g_sctx);
}

void sim_flash_teardown(void)
{
    for (int i = 0; i < 3; i++) free(g_ad.slots[i].areas);
    memset(&g_ad, 0, sizeof g_ad);
    sim_reset_flash_areas();
    sim_reset_context();
}

int sim_run_boot_go(const uint8_t *data, size_t size, struct boot_rsp *rsp)
{
    int rc;
    memset(rsp, 0, sizeof *rsp);
    sim_flash_setup(data, size);
    rc = invoke_boot_go(&g_sctx, &g_ad, rsp, -1);   /* resets areas/context on return */
    sim_flash_teardown();
    return rc;
}

/* Hardware rollback-protection NV counter (csupport/security_cnt.c asks the sim for it):
 * reset to 0 for every input by sim_flash_setup(). */
int sim_get_nv_counter_for_image(uint32_t image_index, uint32_t *data)
{ (void)image_index; *data = g_nv_counter; return 0; }
int sim_set_nv_counter_for_image(uint32_t image_index, uint32_t value)
{ (void)image_index; g_nv_counter = value; return 0; }
