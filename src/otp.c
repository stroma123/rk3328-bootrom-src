/* SPDX-License-Identifier: GPL-2.0 */
/*
 * otp.c - secure OTP (OTP_S) controller driver @ 0xff0a0000.
 *
 * Per the RK3328 TRM this 0xff0a0000 block is the secure OTP (OTP_S). The ROM
 * supports two OTP read protocols selected by the g_otp_variant flag (set in
 * read_security_config()). Both target the OTP block; the controller base
 * pointer was recovered from the ROM's immediate offsets:
 *     proto "a": primary block @ 0xff0a0000, large-field block @ 0xff270000
 *     proto "b": block @ 0xff0a0000
 *
 * NOTE: otp_read_proto_a/_b are the most hardware-specific routines in the ROM.
 * Ghidra lost the base-pointer register setup (shown as 'unaff_wNN'); the base
 * values below are reconstructed from the immediate arithmetic (-0xf60000 ->
 * 0xff0a0000, -0xd90000 -> 0xff270000). The programmed register sequence is
 * reproduced verbatim. Treat field semantics as UNCERTAIN.
 *
 * Behaviour-preserving reconstruction from Ghidra decompiler output.
 */
#include "bootrom.h"

#define OTP_BASE_A    0xff0a0000u
#define OTP_BASE_A_HI 0xff270000u   /* used only for the 0x3c0-sized field */
#define SGRF_MASK_REG   0xff0d0014u   /* DAT_ffff49a0 / 49ac                   */
#define CRU_OTP_SRST  0xff440318u   /* DAT_ffff49a4 / 49b0 / 49d8            */

/* Bounded "wait until (reg & bit) matches want", matching the ROM's
 * -0x2711 (==10001) iteration budget with a 1-unit delay per spin. */
#define OTP_WAIT(reg, shift, want)                                   \
    do {                                                              \
        int _i = -0x2711;                                             \
        while ((((read32(reg) >> (shift)) & 1) != (want))) {          \
            if (++_i == 0) return;                                    \
            rom_delay(1);                                             \
        }                                                             \
    } while (0)

/*
 * ffff10ac - otp_read_proto_a
 * Reads 'n' words starting at word address 'addr' (addr*4 = byte offset).
 * Field size selects the controller base. Each word is assembled from four
 * byte reads out of the data window.
 */
int otp_read_proto_a(uint32_t *dst, int addr, uint32_t n)
{
    uint32_t off = (uint32_t)addr * 4;
    uint32_t base;
    uint32_t ctrl;

    if (off < 0x200) {
        ctrl = 0x2000000;
        base = OTP_BASE_A;
        write32(SGRF_MASK_REG, ctrl);
        write32(SGRF_MASK_REG, 0x4000400);
    } else if ((off - 0x200) <= 0x1bf) {
        ctrl = 0x2000200;
        base = OTP_BASE_A;
        write32(SGRF_MASK_REG, ctrl);
        write32(SGRF_MASK_REG, 0x4000400);
    } else if ((off & 0xffffffc0) == 0x3c0) {
        base = OTP_BASE_A_HI;
        write32(SGRF_MASK_REG, 0x2000200);
        write32(SGRF_MASK_REG, 0x4000000);
    } else {
        return -1;                       /* out of supported range */
    }

    write32(SGRF_MASK_REG, 0x8000800);
    rom_delay(5);
    write32(CRU_OTP_SRST, 0x200020); rom_delay(5);
    write32(CRU_OTP_SRST, 0x200000); rom_delay(5);

    for (uint32_t w = 0; w < n; w++) {
        uint32_t val = 0;
        for (uint32_t b = 0; b < 4; b++) {
            write32(base + 0x20, 0x40004);
            write32(base + 0x28, 0xffff0000);
            write32(base + 0x20, 0xff000200);      /* DAT_ffff49a8 */
            write32(base + 0x24, 0xffff0002);
            write32(base + 0x1000, 0xfc);
            write32(base + 0x1004, off & 0xff);
            write32(base + 0x1008, (off >> 8) & 0xff);
            write32(base + 0x20, 0x10001);
            { int i = -0x2711;
              while (((read32(base + 0x304) >> 1) & 1) == 0) {
                  if (++i == 0) return -1; rom_delay(1); } }
            write32(base + 0x304, 0xffff0002);
            /* second phase: fetch the data byte */
            write32(base + 0x24, 0xffff0006);
            write32(base + 0x1000, 0); write32(base + 0x1004, 0);
            write32(base + 0x1008, 0x40); write32(base + 0x100c, 0x40);
            write32(base + 0x1010, 0); write32(base + 0x1014, 2);
            write32(base + 0x1018, 0x80);
            write32(base + 0x20, 0x10001);
            { int i = -0x2711;
              while (((read32(base + 0x304) >> 1) & 1) == 0) {
                  if (++i == 0) return -1; rom_delay(1); } }
            write32(base + 0x304, 0xffff0002);
            write32(base + 0x304, 0xffff0003);
            val |= (read32(base + 0x2020) & 0xff) << ((b & 3) * 8);
            off++;
        }
        *dst++ = val;
    }
    return 0;
}

/*
 * ffff13ac - otp_read_proto_b
 * Simpler protocol variant: one strobe per byte, polling status bit 2.
 */
int otp_read_proto_b(uint32_t *dst, int addr, uint32_t n)
{
    uint32_t off = (uint32_t)addr * 4;
    uint32_t base = OTP_BASE_A;
    uint32_t ctrl;

    if (off < 0x200) {
        ctrl = 0x2000000;
        write32(SGRF_MASK_REG, ctrl);
        write32(SGRF_MASK_REG, 0x4000400);
    } else if ((off - 0x200) <= 0x1bf) {
        ctrl = 0x2000200;
        write32(SGRF_MASK_REG, ctrl);
        write32(SGRF_MASK_REG, 0x4000400);
    } else if ((off & 0xffffffc0) == 0x3c0) {
        base = OTP_BASE_A_HI;
        write32(SGRF_MASK_REG, 0x2000200);
        write32(SGRF_MASK_REG, 0x4000000);
    } else {
        return -1;
    }

    write32(CRU_OTP_SRST, 0x200020); rom_delay(5);
    write32(base + 0x100, 0x10001);    rom_delay(5);
    write32(CRU_OTP_SRST, 0x200000); rom_delay(5);

    for (uint32_t w = 0; w < n; w++) {
        uint32_t val = 0;
        for (uint32_t b = 0; b < 4; b++) {
            write32(base + 0x104, off | 0xffff0000);
            write32(base + 0x108, 0x10001);
            { int i = -0x2711;
              while (((read32(base + 0x304) >> 2) & 1) == 0) {
                  if (++i == 0) return -1; rom_delay(1); } }
            write32(base + 0x304, 0xffff0004);
            val |= (read32(base + 0x124) & 0xff) << ((b & 3) * 8);
            off++;
        }
        *dst++ = val;
    }
    write32(base + 0x100, 0x10000);
    return 0;
}

/*
 * ffff156c - otp_read
 * Dispatches to the protocol selected by g_otp_variant.
 */
int otp_read(void *dst, int addr_words, uint32_t nwords)
{
    if (g_otp_variant == 0)
        return otp_read_proto_a((uint32_t *)dst, addr_words, nwords);
    else
        return otp_read_proto_b((uint32_t *)dst, addr_words, nwords);
}

/*
 * ffff159c - otp_init
 * Powers up and resets the OTP analog block through a sequence of SGRF
 * write-enable-masked writes (0xffff00xx form) and CRU soft-resets, polling
 * ready/lock bits between steps. The two near-identical halves correspond to
 * the two power-up passes in the ROM. Reconstructed verbatim.
 */
void otp_init(void)
{
    const uint32_t R_MASK  = 0xff0d0014u; /* DAT_ffff49b4 */
    const uint32_t R_20    = 0xff0a0020u; /* DAT_ffff49b8 */
    const uint32_t R_28    = 0xff0a0028u; /* DAT_ffff49bc */
    const uint32_t V_C0    = 0x3a003a00u; /* DAT_ffff49c0 */
    const uint32_t R_24    = 0xff0a0024u; /* DAT_ffff49c4 */
    const uint32_t R_1000  = 0xff0a1000u; /* DAT_ffff49c8 */
    const uint32_t R_304   = 0xff0a0304u; /* DAT_ffff49cc */
    const uint32_t R_1004  = 0xff0a1004u; /* DAT_ffff49d0 */
    const uint32_t R_2c    = 0xff0a002cu; /* DAT_ffff49d4 */
    const uint32_t R_SRST  = 0xff440318u; /* DAT_ffff49d8 */

    g_otp_variant = 0;

    write32(R_MASK, 0x8000800);
    write32(R_20, 0x40004);
    write32(R_28, 0xffff0000);
    write32(R_20, V_C0);
    write32(R_24, 0xffff0001);
    write32(R_1000, 0xbf);
    write32(R_20, 0x10001);
    OTP_WAIT(R_304, 1, 1);

    write32(R_304, 0xffff0002);
    write32(R_24,  0xffff0002);
    write32(R_1000, 1);
    write32(R_1004, 0xbf);
    write32(R_20, 0x10001);
    OTP_WAIT(R_304, 1, 1);
    write32(R_304, 0xffff0002);
    OTP_WAIT(R_2c, 4, 0);

    write32(R_24, 0xffff0002);
    write32(R_1000, 2);
    write32(R_1004, 0xbf);
    write32(R_20, 0x10001);
    OTP_WAIT(R_304, 1, 1);
    write32(R_304, 0xffff0002);
    OTP_WAIT(R_2c, 4, 1);

    /* ---- second pass: toggle the soft-reset and repeat enable ---------- */
    write32(R_MASK, 0x2000200);
    write32(R_MASK, 0x8000800);
    rom_delay(5);
    write32(R_SRST, 0x200020); rom_delay(5);
    write32(R_SRST, 0x200000); rom_delay(5);

    write32(R_20, 0x40004);
    write32(R_28, 0xffff0000);
    write32(R_20, V_C0);
    write32(R_24, 0xffff0001);
    write32(R_1000, 0xbf);
    write32(R_20, 0x10001);
    OTP_WAIT(R_304, 1, 1);

    write32(R_304, 0xffff0002);
    write32(R_24, 0xffff0002);
    write32(R_1000, 1);
    write32(R_1004, 0xbf);
    write32(R_20, 0x10001);
    OTP_WAIT(R_304, 1, 1);
    write32(R_304, 0xffff0002);
    OTP_WAIT(R_2c, 4, 0);

    write32(R_24, 0xffff0002);
    write32(R_1000, 2);
    write32(R_1004, 0xbf);
    write32(R_20, 0x10001);
    OTP_WAIT(R_304, 1, 1);
    write32(R_304, 0xffff0002);
    OTP_WAIT(R_2c, 4, 1);
}
