/* SPDX-License-Identifier: GPL-2.0 */
/*
 * efuse.c - secure eFuse (EFUSE_S) controller driver @ 0xff0b0000.
 *
 * Per the RK3328 TRM this 0xff0b0000 block is the secure eFuse (EFUSE_S). It
 * holds security configuration bits (secure-boot enable, key hashes,
 * lifecycle). This module reads rows, programs individual bits, and provides
 * the bit-counting / descriptor-driven programming helpers the ROM uses.
 * Register addresses are the exact literals from the ROM constant pool.
 *
 * Behaviour-preserving reconstruction from Ghidra decompiler output.
 */
#include "bootrom.h"

#define EFUSE_PWR_REG   0xff0b0000u   /* power/clock enable                     */
#define EFUSE_CMD_REG   0xff0b001cu   /* command + row address (DAT_ffff4c4c/58)*/
#define EFUSE_DATA_REG  0xff0b0020u   /* read/write data (DAT_ffff4c50/5c)      */
#define EFUSE_MASK_REG  0xff0d0014u   /* SGRF write-enable mask (DAT_ffff4c54)  */
#define EFUSE_RST_REG   0xff230000u   /* reset/clock bit used around programming*/

/*
 * ffff3fe4 - efuse_read
 * Reads 'count' 32-bit words starting at eFuse row 'row' into dst.
 * Command sequence (1 -> 0xc -> per-word read -> 1) matches the ROM exactly.
 */
int efuse_read(void *dst, int row, int count)
{
    uint32_t *out = (uint32_t *)dst;

    setbits32(EFUSE_PWR_REG, 0x41);
    write32(EFUSE_CMD_REG, 1);    rom_delay(1);
    write32(EFUSE_CMD_REG, 0xc);  rom_delay(1);

    if (count != 0) {
        uint32_t cmd = ((uint32_t)row << 16) | 0xe;
        do {
            write32(EFUSE_CMD_REG, cmd - 2); rom_delay(1);
            write32(EFUSE_CMD_REG, cmd);     rom_delay(1);
            *out = read32(EFUSE_DATA_REG);
            write32(EFUSE_CMD_REG, cmd - 2);
            out++;
            count--;
            cmd += 0x10000;        /* advance to next row */
        } while (count != 0);
    }
    write32(EFUSE_CMD_REG, 1); rom_delay(1);
    return 0;
}

/*
 * ffff40b8 - efuse_program_bits
 * Blows the bits set in 'mask' of eFuse row 'row' (row < 32). Each set bit is
 * programmed with a strobe sequence; the surrounding reset/mask-enable gating
 * matches the ROM.
 */
int efuse_program_bits(uint32_t row, uint32_t mask)
{
    if (row >= 0x20)
        return -1;

    if (mask != 0) {
        clrbits32(EFUSE_RST_REG, 0x8);
        rom_delay(1000);
        write32(EFUSE_MASK_REG, 0x800080);        /* unlock eFuse writes via SGRF */
        setbits32(EFUSE_PWR_REG, 0x20);

        write32(EFUSE_CMD_REG, 0xd); rom_delay(1);
        write32(EFUSE_CMD_REG, 0x0); rom_delay(1);

        uint32_t strobe = row << 16;
        for (uint32_t bit = 0; bit != 0x20; bit++) {
            if ((1u << (bit & 0x1f)) & mask) {
                write32(EFUSE_DATA_REG, mask);
                write32(EFUSE_CMD_REG, strobe);     rom_delay(1);
                write32(EFUSE_CMD_REG, strobe + 2); rom_delay(1);
                write32(EFUSE_CMD_REG, strobe);     rom_delay(1);
            }
            strobe += 0x200000;                   /* next bit position */
        }
        rom_delay(1);
        write32(EFUSE_CMD_REG, 0xd); rom_delay(1);
        clrbits32(EFUSE_PWR_REG, 0x20);
        write32(EFUSE_MASK_REG, 0x800000);          /* re-lock */
        setbits32(EFUSE_RST_REG, 0x8);
        rom_delay_ms(2);
    }
    return 0;
}

/*
 * ffff4204 - efuse_write_verify
 * Programs only the bits of 'mask' that are not already set (read-modify),
 * then re-reads to confirm. Returns non-zero if any requested bit failed.
 */
int efuse_write_verify(uint32_t row, uint32_t mask)
{
    int failed = 0;
    uint32_t cur = 0;

    if (mask != 0) {
        efuse_read(&cur, row, 1);
        efuse_program_bits(row, mask & ~cur);
        cur = 0;
        efuse_read(&cur, row, 1);
        failed = (~cur & mask) != 0;
    }
    return failed;
}

/*
 * ffff0138 - efuse_count_bits
 * Sums the population count of 'field_count' consecutive eFuse rows starting at
 * row 0x13 (field_count==1) or 0x14 (field_count==2). Used to size a
 * programmable key/field. Returns 1 on bad args.
 */
int efuse_count_bits(int field_count, uint32_t *out)
{
    uint32_t word = 0;
    int base, total, i;

    if (out == NULL)
        return 1;

    base = 0x13;
    if (field_count != 1) {
        if (field_count != 2)
            return 1;
        base = 0x14;
    }

    total = 0;
    for (i = 0; i < field_count; i++) {
        efuse_read(&word, base + i, 1);
        for (uint32_t v = word; v != 0; v &= (v - 1))   /* Kernighan popcount */
            total++;
    }
    *out = total;
    return 0;
}

/*
 * ffff01e0 - efuse_program_from_desc
 * Programs eFuse from the pending descriptor left in SRAM by
 * secure_boot_header_verify(): width mode (1 or 2), bit budget, and the number
 * of bits to burn. Writes 32 bits at a time via efuse_write_verify().
 */
int efuse_program_from_desc(void)
{
    if (g_efuse_prog_valid != 0 && g_efuse_prog_cnt >= g_efuse_prog_max &&
        g_efuse_prog_max != g_efuse_prog_cnt) {

        int base;
        uint32_t fields;

        if (g_efuse_prog_mode == 2) {
            if (g_efuse_prog_cnt > 0x3f) return 1;
            base = 0x14; fields = 2;
        } else if (g_efuse_prog_mode == 1) {
            if (g_efuse_prog_cnt > 0x1f) return 1;
            base = 0x13; fields = 1;
        } else {
            return 1;
        }

        uint32_t remaining = g_efuse_prog_cnt;
        for (uint32_t i = 0; i < fields; i++) {
            uint32_t chunk = remaining > 0x1f ? 0x20 : remaining;
            uint32_t m = 0xffffffffu >> ((0x20 - chunk) & 0x1f);
            if (efuse_write_verify(base + i, m) != 0)
                return 1;
            remaining -= chunk;
        }
    }
    return 0;
}
