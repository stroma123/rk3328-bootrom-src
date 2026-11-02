/* SPDX-License-Identifier: GPL-2.0 */
/*
 * secure_boot.c - secure-boot configuration probe and signed-header verifier.
 *
 * read_security_config() runs once at startup to discover whether secure boot
 * is enforced (from OTP/eFuse) and which OTP read-protocol variant the part has.
 * secure_boot_header_verify() validates a loaded image's "RSAK" header: key
 * provisioning into eFuse, key-hash comparison against OTP, and the SHA/RSA
 * signature chain.
 *
 * Both functions return the ROM's "true == reject/fail" boolean sense where
 * noted. Behaviour-preserving reconstruction from Ghidra decompiler output.
 */
#include "bootrom.h"

/*
 * ffff04b8 - read_security_config
 * Reads eFuse word 0 and, using 4-bit majority voting, decides:
 *   - whether the OTP block is present (g_otp_present) and its protocol
 *     variant (g_otp_variant),
 *   - whether secure boot is enabled (g_secure_boot) and the key length
 *     (g_key_words), read from OTP word 0x80,
 *   - a lifecycle bit from eFuse word 0x17 (-> 0xff0b0008).
 * The majority voting tolerates a single flipped redundancy bit per field.
 */
int read_security_config(void)
{
    uint32_t w = 0;
    int ones;
    uint32_t i;

    g_otp_present = 0;
    setbits32(0xff230000, 8);
    setbits32(0xff230004, 8);                 /* DAT_ffff0744 */
    rom_delay(1000);

    efuse_read(&w, 0, 1);

    /* count cleared bits in nibble [3:0] (redundancy-coded "present") */
    ones = 0;
    for (i = 0; i != 4; i++)
        ones += ((1u << (i & 0x1f)) & (~w) & 0xf) != 0;

    if (ones < 2) {
        otp_init();
        g_otp_present = 1;

        ones = 0;
        for (i = 0; i != 4; i++)
            ones += ((1u << (i & 0x1f)) & ((~w) >> 8) & 0xf) != 0;
        if (ones < 2)
            g_otp_variant = 1;

        w = 0;
        otp_read(&w, 0x80, 1);
        if ((w & 0xff) == 0xff) {
            g_secure_boot = 1;
            g_key_words = (w >> 8) & 0xff;
        } else {
            if (g_secure_boot != 1) {
                write32(0xff0d0000, 0xf000f);
                goto lifecycle;
            }
        }
    } else {
        ones = 0;
        for (i = 0; i != 4; i++)
            ones += ((1u << (i & 0x1f)) & ((~w) >> 4) & 0xf) != 0;
        if (ones >= 2) {
            if (g_secure_boot != 1) {
                write32(0xff0d0000, 0xf000f);
                goto lifecycle;
            }
        } else {
            g_secure_boot = 1;
        }
    }

    crypto_clk_enable();

lifecycle:
    w = 0;
    efuse_read(&w, 0x17, 1);
    if ((int8_t)w == -1)
        write32(0xff0b0008, 1);               /* DAT_ffff0748 */
    return 0;
}

/*
 * ffff02bc - secure_boot_header_verify
 * Validates the "RSAK" header at 'hdr'. Returns true (non-zero) to REJECT,
 * false to accept - matching the ROM.
 *
 * Steps (preserved from the decompiler):
 *   1. magic check (*hdr == "RSAK").
 *   2. optional eFuse field provisioning request (flag bit 8, field count bits
 *      [11:9]) staged into the SRAM eFuse descriptor.
 *   3. key authentication:
 *        - if g_otp_present flag (0xff090018) set: compare a 256-byte OTP
 *          region against the header key (0x100 bytes @ hdr+0x20).
 *        - otherwise: hash the key with the SHA engine and compare 32 bytes.
 *   4. image signature size sanity, then rsa_verify_signature().
 */
int secure_boot_header_verify(const void *hdr)
{
    const uint8_t *h = (const uint8_t *)hdr;
    const uint32_t *w = (const uint32_t *)hdr;
    uint8_t  hashbuf[256];
    const void *keyctx;
    uint32_t field_bits = 0;
    int reject = 1;
    int n, r;

    if (w[0] != MAGIC_RSAK)                    /* "RSAK" */
        return 1;

    /* reset pending eFuse descriptor */
    g_efuse_prog_mode  = 0;
    g_efuse_prog_valid = 0;
    g_efuse_prog_max   = 0;
    g_efuse_prog_cnt   = 0;

    if ((w[2] >> 8) & 1) {
        uint16_t cur = *(const uint16_t *)(h + 0x10);
        uint16_t req = *(const uint16_t *)(h + 0x12);
        if (cur < req) {                       /* cannot shrink -> reject state */
            g_efuse_prog_mode = 0; g_efuse_prog_cnt = 0;
            g_efuse_prog_max = 0;  g_efuse_prog_valid = 0;
            return 1;
        }
        uint32_t fc = (w[2] >> 9) & 7;
        if (efuse_count_bits(fc, &field_bits) != 0)
            return 1;
        if (cur < field_bits)
            return 1;
        if (((h[9] >> 4) & 1) == 0) {
            g_efuse_prog_cnt   = *(const uint16_t *)(h + 0x12);
            g_efuse_prog_max   = field_bits;
            g_efuse_prog_valid = 1;
            g_efuse_prog_mode  = fc;
        }
    }

    if (g_otp_present == 1) {
        /* compare header key against the 256-byte OTP key region */
        rom_memset(hashbuf, 0, 0x40);
        if (otp_read(hashbuf, 0, 0x40) != 0)  /* read 0x40 words */
            return 1;
        keyctx = h + 0x20;
        if ((g_key_words - 1u) > 0x3f)
            g_key_words = 0x40;
        n = (int)(g_key_words << 2);
        r = rom_memcmp(hashbuf, h + 0x20, 0x100);
        (void)r;                                /* key compared above */
    } else {
        /* hash the key and compare 32 bytes (SHA-256) */
        keyctx = h + 0x20;
        otp_read(hashbuf, 1, 8);               /* read device id salt (OTP) */
        sha_start(0x200);
        sha_update_dma(h + 0x20, 0x200);
        sha_read_digest(hashbuf);
        n = 0x20;
    }

    r = rom_memcmp(hashbuf, keyctx, n);
    if (r == 0 && ((w[3] & 0xffff) << 2) < 0x701) {
        r = rsa_verify_signature(hdr, 0);       /* body length filled by caller */
        reject = (r != 0);
    }
    return reject;
}
