/* SPDX-License-Identifier: GPL-2.0 */
/*
 * clock.c - Clock & Reset Unit (CRU @ 0xff440000) bring-up.
 *
 * cru_early_init() sets up the initial clock gates/dividers; cru_pll_init()
 * raises the CPU/bus clock from the 24 MHz boot clock to 200 or 400 MHz
 * (selected by a strap read from 0xff440094) and records the new udelay
 * reference. Register addresses and the magic divider/PLL values are the exact
 * literals from the ROM constant pool.
 *
 * The PLL configuration words (e.g. 0x7fff40c8) are opaque hardware settings;
 * they are reproduced verbatim and NOT interpreted.
 *
 * Behaviour-preserving reconstruction from Ghidra decompiler output.
 */
#include "bootrom.h"

/*
 * ffff18d4 - cru_early_init
 */
void cru_early_init(void)
{
    write32(0xff440080, 0x10000);
    write32(0xff440080, 0x10000000);
    write32(0xff440100, 0x7fdf2000);    /* DAT_ffff49e0 -> 0xff440100 */
    write32(0xff440104, 0x737f0000);
    write32(0xff440114, 0xdf008100);    /* DAT_ffff49ec -> 0xff440114 */
    write32(0xff440170, 0x00df0040);    /* DAT_ffff49f4 -> 0xff440170 */
    write32(0xff440174, 0x00730000);
}

/*
 * ffff194c - cru_pll_init
 * Only runs while still on the slow boot clock (get_timer_clock() < 200).
 * Programs the main PLL, picks 200/400 MHz from the 0xff440094 strap, and
 * updates the delay reference via set_timer_clock().
 */
void cru_pll_init(void)
{
    uint32_t new_mhz;

    if (get_timer_clock() >= 200)
        return;

    write32(0xff440004, 0x20002000);
    write32(0xff440004, 0x10001000);
    write32(0xff440000, 0x7fff40c8);    /* DAT_ffff4a04 */
    write32(0xff440004, 0x01ff0043);    /* DAT_ffff4a08 */

    write32(0xff440064, 0x20000000);
    write32(0xff440064, 0x10001000);
    write32(0xff440060, 0x7fff30c0);    /* DAT_ffff4a10 */
    write32(0xff440064, 0x01ff0042);    /* DAT_ffff4a18 */
    rom_delay(10);
    write32(0xff440004, 0x20000000);
    write32(0xff440064, 0x20000000);
    rom_delay(1000);

    if ((read32(0xff440094) & 0x3f) == 0) {
        write32(0xff440100, 0x7fdf2500); /* DAT_ffff4a28 : 400 MHz profile */
        new_mhz = 400;
    } else {
        write32(0xff440100, 0x7fdf2501); /* DAT_ffff4a20 : 200 MHz profile */
        new_mhz = 200;
    }

    write32(0xff440104, 0x737f1113);     /* DAT_ffff4a2c */
    write32(0xff440170, 0x00df0043);     /* DAT_ffff4a34 */
    write32(0xff440174, 0x00733001);     /* DAT_ffff4a3c */
    write32(0xff440080, 0x10001);
    write32(0xff440080, 0x10001000);

    set_timer_clock(new_mhz);
}
