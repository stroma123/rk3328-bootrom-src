/* SPDX-License-Identifier: GPL-2.0 */
/*
 * boot.c - top-level boot flow: device table iteration, image load + verify +
 *          launch, and the ROM entry point bootrom_main().
 *
 * The boot-device table (PTR_FUN_ffff4600) holds 4 driver descriptors, each a
 * 0x20-byte struct of function pointers + counts. Layout recovered from usage:
 *
 *   struct boot_driver {
 *       int (*probe)(void);                            // +0x00
 *       int (*read_blocks)(int lba,uintptr buf,u32 n); // +0x08
 *       int (*read_or_id)(int,uintptr,void*);          // +0x10
 *       uint32_t count;                                // +0x18
 *       uint32_t param;                                // +0x1c
 *   };
 *
 * The four entries map to: eMMC, SPI-NOR, SPI-NAND, SD (from their probe fns).
 *
 * Behaviour-preserving reconstruction from Ghidra decompiler output.
 */
#include "bootrom.h"

struct boot_driver {
    int      (*probe)(void);                                    /* +0x00 */
    int      (*read_blocks)(int lba, uintptr_t buf, uint32_t n);/* +0x08 */
    int      (*read_or_id)(int, uintptr_t, void *);             /* +0x10 */
    uint32_t  count;                                            /* +0x18 */
    uint32_t  param;                                            /* +0x1c */
};

/*
 * Boot-device descriptor table (ROM data @ 0xffff4600), transcribed exactly
 * (probe fn, read_blocks fn, read_or_id fn, count, param). The four entries are
 * eMMC, SPI-NOR, SPI-NAND and SD. Function-pointer casts bridge the minor
 * signature differences between the SPI and MMC read routines (as the ROM does
 * by calling through a uniform slot).
 */
typedef int (*rd_blk_t)(int, uintptr_t, uint32_t);
typedef int (*rd_id_t)(int, uintptr_t, void *);

struct boot_driver boot_device_table[4] = {
    /* eMMC   @ffff4600 */ { emmc_probe,          (rd_blk_t)mmc_read_blocks,
                             (rd_id_t)mmc_read_block_lba, 5, 2 },
    /* SPI-NOR@ffff4620 */ { spiflash_probe,      (rd_blk_t)flash_read_image,
                             (rd_id_t)flash_find_idb,     0xd, 3 },
    /* SPI-NAND@ffff4640*/ { spiflash_probe_alt,  (rd_blk_t)flash_read_image,
                             (rd_id_t)flash_find_idb,     0xd, 4 },
    /* SD     @ffff4660 */ { sd_probe,            (rd_blk_t)mmc_read_blocks,
                             (rd_id_t)mmc_read_block_lba, 5, 5 },
};

#define IDB_MAGIC   MAGIC_IDB_SECTOR0      /* 0xfcdc8c3b (DAT_ffff4b10) */

/*
 * ffff2ba0 - boot_load_image
 * Walks the entries exposed by a probed driver, loads the IDB (sector 0 magic
 * 0xfcdc8c3b), optionally RC4-decodes the 512-byte sectors, verifies the
 * secure chain (header + SHA + RSA) when g_secure_boot is set, and launches the
 * loaded code. Close transliteration of the ROM; the inner loop structure and
 * all SRAM/driver accesses are preserved.
 */
void boot_load_image(uintptr_t driver)
{
    struct boot_driver *d = (struct boot_driver *)driver;
    uint32_t idx;

    g_boot_stage = d->param;
    if (d->count == 0)
        return;

    for (idx = 0; idx < d->count; idx++) {
        int found_off = 0;
        uint32_t *sec = (uint32_t *)(uintptr_t)IDB_LOAD_BUF;

        int rc = d->read_or_id(idx, IDB_LOAD_BUF, &found_off);
        if (rc < 0)
            return;
        if (rc != 0 || *sec != IDB_MAGIC)         /* DAT_ffff4b10 */
            continue;

        rc4_crypt((uint8_t *)sec, 0x200);         /* FUN_ffff3f60 */

        /* IDB header fields (16-bit) */
        uint16_t nsect  = *(uint16_t *)((uint8_t *)IDB_LOAD_BUF + 0x1fc);
        uint16_t boff   = *(uint16_t *)((uint8_t *)IDB_LOAD_BUF + 0x1fa);
        uint32_t pages  = (nsect > 4) ? nsect : 10;
        uint32_t copies = boff;
        if ((copies <= pages && copies != pages) ||
            ((boff - 4) & 0xffff) > 0x3fc || (boff & 3) != 0)
            copies = 4;

        g_idb_src_addr = found_off;             /* _DAT_ff090014, NOT g_boot_stage */
        if (pages == 0)
            continue;

        uint32_t loaded = *(uint32_t *)((uint8_t *)IDB_LOAD_BUF + 8) & 1;  /* flags */
        int base = found_off + *(uint16_t *)((uint8_t *)IDB_LOAD_BUF + 0xc);

        uint32_t *cur = (uint32_t *)((uint8_t *)IDB_LOAD_BUF + 0);
        for (uint32_t off = 0; off < pages; off += 4) {
            if (d->read_blocks(base + off, (uintptr_t)cur, 0x800) != 0)
                goto next_entry;

            if (loaded == 0) {                      /* RC4-decode each 512B page */
                rc4_crypt((uint8_t *)cur, 0x200);
                rc4_crypt((uint8_t *)cur + 0x200, 0x200);
                rc4_crypt((uint8_t *)cur + 0x400, 0x200);
                rc4_crypt((uint8_t *)cur + 0x600, 0x200);
            }

            if (off == 0) {
                if (g_secure_boot == 0) {
                    if (*cur != MAGIC_RSAK)         /* "RSAK" (DAT_ffff073c) */
                        goto tail_check;
                } else {
                    if (secure_boot_header_verify(cur) != 0)
                        goto next_entry;
                    crypto_copy_bigint(0xff09003c, (uint8_t *)cur + 200 * 4, 0x44);
                    sha_start(copies * 0x200 - 0x800);
                }
            } else {
tail_check:
                if (copies - 4 == off) {
                    if (g_secure_boot != 0) {
                        sha_update_dma(cur, 0x800);
                        if (sha_final_compare((void *)0xff09003c) != 0)
                            goto next_entry;
                    }
                    /* final section must carry the "RK32" end tag then launch */
                    if (*(uint32_t *)(uintptr_t)IDB_LOAD_BUF != MAGIC_RK32 ||
                        ((int (*)(void))(uintptr_t)0xff091004)() != 0)
                        goto next_entry;
                    if (g_secure_boot != 0)
                        sha_start((pages - copies) * 0x200);
                    cur = (uint32_t *)0;            /* loaded & launched */
                } else {
                    if (g_secure_boot != 0)
                        sha_update_dma(cur, 0x800);
                    cur += 0x200;                   /* advance 0x800 bytes */
                }
            }
        }

        if (g_secure_boot != 0) {
            if (sha_final_compare((void *)0xff090060) != 0)
                goto next_entry;
            efuse_program_from_desc();
        }
        jump_to_code((void (*)(void))0);           /* FUN_ffff45f8(0) : launch */
next_entry:;
    }
}

/*
 * ffff2e68 - boot_try_devices
 * Probes each of the 4 boot drivers in order; on a successful probe, attempts
 * to load and launch an image from it.
 */
void boot_try_devices(void)
{
    struct boot_driver *d = boot_device_table;
    for (int i = 4; i != 0; i--) {
        if (d->probe() == 0)
            boot_load_image((uintptr_t)d);
        d++;
    }
}

/*
 * ffff4288 - bootrom_main  (ROM entry after the reset stub)
 * Startup sequence:
 *   set 24 MHz delay clock -> early CRU init -> clear secure flag ->
 *   read security config -> raise PLL -> try boot devices ->
 *   fall into USB maskrom download mode -> spin forever.
 */
void bootrom_main(void)
{
    set_timer_clock(0x18);          /* 24 MHz reference */
    cru_early_init();
    g_secure_boot = 0;
    read_security_config();
    cru_pll_init();
    g_boot_stage = 0;
    boot_try_devices();
    usb_maskrom_mode();
    for (;;)
        ;
}
