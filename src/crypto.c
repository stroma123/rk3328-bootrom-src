/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crypto.c - hardware crypto engine @ 0xff060000 : SHA-256, RSA-2048, and the
 *            RC4 obfuscation used on stored boot images.
 *
 * The engine is tagged in ROM by the "RK32" magic (0x32334b52). Register
 * addresses below are the exact literals from the constant pool. Digest and
 * RSA-operand register banks were identified from the access patterns.
 *
 * Behaviour-preserving reconstruction from Ghidra decompiler output.
 */
#include "bootrom.h"

/* Crypto register map (verbatim literals from the ROM pool) */
#define CRY_GLOBAL      0xff060000u   /* _DAT_ff060000 : DMA/global mode        */
#define CRY_INTSTS      0xff060008u   /* busy/done status bits                  */
#define CRY_CONF        0xff06000cu   /* hash/rsa enable                        */
#define CRY_HASH_CTRL   0xff060180u   /* hash control                           */
#define CRY_HASH_LEN    0xff060188u   /* message length / DMA src addr          */
#define CRY_DMA_LEN     0xff06018cu   /* DMA word count / digest readback       */
#define CRY_RSA_CTRL    0xff060280u
#define CRY_CLK_GATE    0xff440150u   /* CRU gate (DAT_ffff4998)                 */
#define CRY_CLK_VAL     0x009f0087u   /* gate value (DAT_ffff4994)              */
#define SGRF_CRY_REG    0xff0d0010u   /* secure-GRF crypto enable (DAT_ffff499c)*/
#define CRU_RSA_SRST    0xff440310u   /* DAT_ffff4934                           */

/*
 * ffff1084 - crypto_clk_enable
 * Ungates the crypto engine clock (CRU) and flips its secure-GRF enable.
 */
void crypto_clk_enable(void)
{
    write32(CRY_CLK_GATE, CRY_CLK_VAL);
    write32(SGRF_CRY_REG, 0x40000000);
}

/*
 * ffff439c - crypto_copy_bigint
 * Thin tail-call over rom_memcpy() in the ROM; used to stage 256-byte (2048-bit)
 * operands into the crypto register banks and to copy signature/key context.
 * Returns the destination.
 */
int crypto_copy_bigint(uintptr_t dst_reg, const void *src, int n)
{
    rom_memcpy((void *)dst_reg, src, (size_t)n);
    return (int)dst_reg;
}

/*
 * ffff0b84 - sha_start
 * Arms the SHA engine for a message of 'msg_len' bytes.
 */
int sha_start(uint32_t msg_len)
{
    setbits32(CRY_CONF, 0x20);
    write32(CRY_HASH_LEN, msg_len);
    write32(CRY_HASH_CTRL, 10);                 /* mode = SHA-256 (UNCERTAIN) */
    write32(CRY_INTSTS, 0x400040);
    while ((read32(CRY_INTSTS) >> 6) & 1)       /* wait for arm-ack */
        ;
    return 0;
}

/*
 * ffff0bd4 - sha_update_dma
 * Feeds 'len' bytes at 'addr' into the hash via DMA (word count = ceil(len/4)).
 */
int sha_update_dma(const void *addr, int len)
{
    while ((read32(CRY_INTSTS) >> 3) & 1)       /* wait for DMA idle */
        ;
    write32(CRY_GLOBAL, 0x10);                  /* enable hash DMA */
    write32(CRY_HASH_LEN, (uint32_t)(uintptr_t)addr);
    write32(CRY_DMA_LEN,  ((uint32_t)len + 3) >> 2);
    write32(CRY_INTSTS, 0x80008);               /* kick */
    return 0;
}

/*
 * ffff0c20 - sha_read_digest
 * Waits for completion and copies the 32-byte (SHA-256) digest out. The
 * read-back address (0xff06018c) is taken verbatim from the ROM.
 */
int sha_read_digest(void *out32)
{
    while ((read32(CRY_INTSTS) >> 3) & 1)
        ;
    while (read32(0xff060184) == 0)             /* wait digest-valid */
        ;
    for (long i = 0; i != 0x20; i += 4)
        *(uint32_t *)((uint8_t *)out32 + i) = read32(CRY_DMA_LEN + i);
    return 0;
}

/*
 * ffff0c68 - sha_final_compare
 * Like sha_read_digest, but compares the result against a caller-supplied
 * 32-byte expected digest instead of returning it. Returns memcmp result.
 */
int sha_final_compare(const void *expected32)
{
    uint32_t digest[8];

    while ((read32(0xff060008) >> 3) & 1)
        ;
    while (read32(0xff060184) == 0)
        ;
    for (long i = 0; i != 0x20; i += 4)
        digest[i / 4] = read32(0xff06018c + i);
    return rom_memcmp(expected32, digest, 0x20);
}

/*
 * ffff0cd0 - rsa_load_operands
 * Loads four 256-byte operand banks (modulus/base/etc.) into the engine and
 * waits for the operation to complete. Used for the second RSA pass.
 */
int rsa_load_operands(const void *a, const void *b, const void *c, const void *d)
{
    write32(CRY_GLOBAL, 0x20);
    crypto_copy_bigint(0xff060400, a, 0x100);
    crypto_copy_bigint(0xff060600, b, 0x100);
    crypto_copy_bigint(0xff060700, c, 0x100);
    crypto_copy_bigint(0xff060500, d, 0x100);
    while ((read32(0xff060008) >> 4) & 1)
        ;
    write32(0xff060008, 0x100010);
    return 0;
}

/*
 * ffff0db4 - rsa_load_and_run
 * Soft-resets the RSA core, loads the four 256-byte operand banks, starts the
 * modular exponentiation and waits for it to finish.
 */
int rsa_load_and_run(const void *a, const void *b, const void *c, const void *d)
{
    write32(CRU_RSA_SRST, 0x100010);
    rom_delay(5);
    write32(CRU_RSA_SRST, 0x100000);
    write32(CRY_RSA_CTRL, 2);
    write32(0xff060008, 0xc000c0);
    while (read32(0xff060008) & 0x90)
        ;
    write32(CRY_GLOBAL, 0x20);
    crypto_copy_bigint(0xff060400, a, 0x100);
    crypto_copy_bigint(0xff060600, b, 0x100);
    crypto_copy_bigint(0xff060700, c, 0x100);
    crypto_copy_bigint(0xff060500, d, 0x100);
    while ((read32(0xff060008) >> 4) & 1)
        ;
    write32(0xff060008, 0x100010);
    return 0;
}

/*
 * ffff0ebc - rsa_read_result_cmp
 * Reads the recovered 32-byte value out of the RSA result bank
 * (0xff060400..0xff06041c) and compares it with the SHA digest staged at
 * 0xff06018c. Returns the memcmp result (0 = signature matches hash).
 */
int rsa_read_result_cmp(void)
{
    uint32_t hash[8];
    uint32_t result[8];

    while ((read32(0xff060008) >> 3) & 1)
        ;
    while (read32(0xff060184) == 0)
        ;
    for (long i = 0; i != 0x20; i += 4)
        hash[i / 4] = read32(0xff06018c + i);

    while ((read32(0xff060008) >> 4) & 1)
        ;
    /* result words are read high-to-low from the 0xff060400 bank */
    result[0] = read32(0xff06041c); result[1] = read32(0xff060418);
    result[2] = read32(0xff060414); result[3] = read32(0xff060410);
    result[4] = read32(0xff06040c); result[5] = read32(0xff060408);
    result[6] = read32(0xff060404); result[7] = read32(0xff060400);

    return rom_memcmp(result, hash, 0x20);
}

/*
 * ffff0fb0 - rsa_verify_signature
 * Full image signature check: run RSA over (key N @ hdr+0x20, ... , signature
 * @ hdr+0x220), then hash the image body and confirm engine completion.
 * 'hdr' points at the signed header; 'len' is the hashed body length.
 * Returns non-zero on success (matches the ROM's bool sense).
 */
int rsa_verify_signature(const void *hdr, int len)
{
    const uint8_t *h = (const uint8_t *)hdr;

    rsa_load_and_run((const void *)(uintptr_t)((uint32_t)(uintptr_t)h + len),
                     h + 0x20, h + 0x120, h + 0x220);

    setbits32(CRY_CONF, 0x20);
    write32(CRY_HASH_LEN, len);
    write32(CRY_HASH_CTRL, 10);
    write32(0xff060008, 0x400040);
    while ((read32(0xff060008) >> 6) & 1)
        ;
    while ((read32(0xff060008) >> 3) & 1)
        ;
    write32(CRY_GLOBAL, 0x10);
    write32(0xff060188, (uint32_t)(uintptr_t)h);
    write32(0xff060190, ((uint32_t)len + 3) >> 2);
    write32(0xff060008, 0x80008);
    return rsa_read_result_cmp() != 0;
}

/*
 * ffff3f60 - rc4_crypt
 * RC4 stream cipher used to obfuscate images in flash/USB download. The 256-byte
 * key schedule is seeded from a fixed table in ROM (constants 0x62987d7a /
 * 0xbe3d3a96 at 0xffff46e0); the state lives in SRAM at 0xff0900f0. XORs 'len'
 * bytes of 'buf' in place.
 */
void rc4_crypt(uint8_t *buf, int len)
{
    volatile uint8_t  *S  = (volatile uint8_t  *)(uintptr_t)RC4_SBOX;
    volatile uint32_t *Sw = (volatile uint32_t *)(uintptr_t)RC4_SBOX;

    /*
     * Seed the 256-byte S-box from the fixed table in ROM (@ 0xffff46e0),
     * copied one 32-bit word at a time exactly as the ROM does. The table is
     * a precomputed permutation, so no keyed KSA is performed - the keystream
     * is fixed. rc4_init_table[] lives in ROM .rodata (see bootrom_rodata.c).
     */
    extern const uint32_t rc4_init_table[64];   /* 256 bytes */
    for (int w = 0; w < 64; w++)
        Sw[w] = rc4_init_table[w];

    uint32_t x = 0, y = 0;
    for (; len != 0; len--) {
        x = (x + 1) & 0xff;
        uint8_t sx = S[x];
        y = (sx + y) & 0xff;
        S[x] = S[y];
        S[y] = sx;
        *buf ^= S[(uint8_t)(S[x] + sx) & 0xff];
        buf++;
    }
}
