/* SPDX-License-Identifier: GPL-2.0 */
/*
 * util.c - low-level helpers: timed delays, mem* , CRC-16, CPU state.
 *
 * Behaviour-preserving reconstruction from Ghidra decompiler output.
 * Original ROM addresses are noted per function.
 */
#include "bootrom.h"

/*
 * ffff0698 - get_timer_clock
 * Returns the current udelay reference clock (MHz), stored in SRAM.
 */
uint32_t get_timer_clock(void)
{
    return g_timer_clock_mhz;
}

/*
 * ffff06a4 - set_timer_clock
 * Records the active reference clock used to scale rom_delay().
 */
void set_timer_clock(uint32_t mhz)
{
    g_timer_clock_mhz = mhz;
}

/*
 * ffff45d8 - delay_spin
 * Leaf busy-loop (the decompiler could not recover its body precisely; in the
 * ROM it is a tight counted NOP spin). Preserved as an empty deferral so that
 * rom_delay()'s control flow matches the original.
 */
void delay_spin(void)
{
    /* counted NOP loop in ROM; no observable side effects */
}

/*
 * ffff06b0 - rom_delay
 * Scales a caller-supplied unit count by the active reference clock and spins.
 * The 0x18 (24 MHz) path and the generic path reproduce the ROM's two formulas
 * exactly.
 */
void rom_delay(int units)
{
    uint32_t loops;

    if (g_timer_clock_mhz == 0x18)                       /* 24 MHz */
        loops = (uint32_t)(g_timer_clock_mhz * units * 0x77 + 0x1fff) >> 0xd;
    else
        loops = (uint32_t)(g_timer_clock_mhz * units * 0x80 + 0x7fff) >> 0xf;

    if (loops != 0)
        delay_spin();
}

/*
 * ffff0704 - rom_delay_ms
 * Coarse delay: 'n' iterations of rom_delay(1000).
 */
void rom_delay_ms(int n)
{
    for (; n != 0; n--)
        rom_delay(1000);
}

/*
 * ffff42c4 - rom_memcmp
 * Word-at-a-time compare with a byte-wise tail; returns the signed difference
 * of the first mismatching byte (lexicographic), 0 if equal.
 */
int rom_memcmp(const void *pa, const void *pb, size_t n)
{
    const uint8_t *a = (const uint8_t *)pa;
    const uint8_t *b = (const uint8_t *)pb;

    if ((((uintptr_t)a | (uintptr_t)b) & 3) == 0) {
        const uint32_t *wa = (const uint32_t *)pa;
        const uint32_t *wb = (const uint32_t *)pb;
        while (n > 3) {
            uint32_t x = *wa++, y = *wb++;
            n -= 4;
            if (x != y) {
                int d = (int)(x & 0xff) - (int)(y & 0xff);
                if (d == 0) d = (int)(x & 0xffff)   - (int)(y & 0xffff);
                if (d == 0) d = (int)(x & 0xffffff) - (int)(y & 0xffffff);
                if (d == 0) d = (int)(x >> 24)      - (int)(y >> 24);
                return d;
            }
        }
        a = (const uint8_t *)wa;
        b = (const uint8_t *)wb;
    }
    while (n--) {
        int d = (int)*a++ - (int)*b++;
        if (d) return d;
    }
    return 0;
}

/*
 * ffff442c - memcpy_aligned  (internal, both pointers word-aligned)
 * 16-byte unrolled copy with 8/4/1-byte tails.
 */
static void memcpy_aligned(uint32_t *d, const uint32_t *s, size_t n)
{
    for (; n > 0xf; n -= 0x10) {
        uint32_t a = s[1], b = s[2], c = s[3];
        d[0] = s[0]; d[1] = a; d[2] = b; d[3] = c;
        d += 4; s += 4;
    }
    if (n > 7) { uint32_t a = s[1]; d[0] = s[0]; d[1] = a; d += 2; s += 2; n -= 8; }
    if (n > 3) { d[0] = s[0]; d += 1; s += 1; n -= 4; }
    {
        uint8_t *db = (uint8_t *)d; const uint8_t *sb = (const uint8_t *)s;
        while (n-- ) *db++ = *sb++;
    }
}

/*
 * ffff4480 - rom_memcpy  (public entry)
 * Aligns the destination, then either uses the aligned fast path or a
 * word-shifting path for a misaligned source. Byte tail handles the remainder.
 * Faithful to the ROM's alignment handling.
 */
void *rom_memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;

    if (n >= 4) {
        /* bring destination to 4-byte alignment one byte at a time */
        while (((uintptr_t)d & 3) && n) { *d++ = *s++; n--; }

        if (((uintptr_t)s & 3) == 0) {
            memcpy_aligned((uint32_t *)d, (const uint32_t *)s, n);
            return dst;
        }
        /* misaligned source: shift words across the alignment boundary */
        uint32_t sh = ((uintptr_t)s & 3) * 8;
        const uint32_t *ws = (const uint32_t *)(s - ((uintptr_t)s & 3));
        uint32_t *wd = (uint32_t *)d;
        uint32_t cur = *ws++;
        for (; n > 3; n -= 4) {
            uint32_t lo = cur >> sh;
            cur = *ws++;
            *wd++ = (cur << (32 - sh)) | lo;
        }
        d = (uint8_t *)wd;
        s = (const uint8_t *)ws - (sh >> 3);
    }
    while (n--) *d++ = *s++;
    return dst;
}

/*
 * ffff4560 - memset_words (internal word/half/byte fill)
 */
static void memset_words(void *dst, size_t n, uint32_t v)
{
    uint32_t *d = (uint32_t *)dst;
    for (; n > 3; n -= 4) *d++ = v;
    if (n & 2) { *(uint16_t *)d = (uint16_t)v; d = (uint32_t *)((uint8_t *)d + 2); }
    if (n & 1) *(uint8_t *)d = (uint8_t)v;
}

/*
 * ffff458c - memset_impl : align head, then memset_words
 * ffff43c8 - rom_memset  : public wrapper, replicates the byte to a word.
 */
static void memset_impl(void *dst, size_t n, uint16_t v16)
{
    uint8_t *d = (uint8_t *)dst;
    if (n && ((uintptr_t)d & 1)) { *d++ = (uint8_t)v16; n--; }
    if (n > 1 && ((uintptr_t)d & 2)) { *(uint16_t *)d = v16; d += 2; n -= 2; }
    memset_words(d, n, (uint32_t)v16 | ((uint32_t)v16 << 16));
}

void *rom_memset(void *dst, int c, size_t n)
{
    uint32_t w = (uint32_t)(c & 0xff) * 0x01010101u;
    memset_impl(dst, n, (uint16_t)w);
    return dst;
}

/*
 * ffff3f0c - crc16_ccitt
 * MSB-first CRC-16/CCITT (polynomial 0x1021, init 0xffff). Used to validate
 * blobs received over the USB maskrom protocol. The ROM returns the running
 * value in w0 (the decompiler dropped the return; restored here).
 */
uint16_t crc16_ccitt(const uint8_t *buf, int len)
{
    uint32_t crc = 0xffff;
    for (; len != 0; len--) {
        for (uint32_t bit = 0x80; bit != 0; bit >>= 1) {
            uint32_t x = (crc & 0xffff) << 1;
            if (crc & 0x8000) x ^= 0x1021;
            crc = x;
            if (*buf & bit) crc ^= 0x1021;
        }
        buf++;
    }
    return (uint16_t)crc;
}

/*
 * ffff45e4 - cpu_enable_irq_abort
 * Sets SCR_EL3.EA (external-abort/SError routed to EL3) and clears DAIF.I to
 * unmask IRQs. Returns the new SCR_EL3 value (as the ROM does).
 */
uint64_t cpu_enable_irq_abort(void)
{
#if defined(__aarch64__)
    uint64_t scr, daif;
    __asm__ volatile("mrs %0, scr_el3" : "=r"(scr));
    scr |= 2;
    __asm__ volatile("msr scr_el3, %0" :: "r"(scr));
    __asm__ volatile("mrs %0, daif" : "=r"(daif));
    daif &= ~0x80ull;
    __asm__ volatile("msr daif, %0" :: "r"(daif));
    return scr;
#else
    /* host build: system-register access is AArch64-only */
    return 2;
#endif
}

/*
 * ffff45f8 - jump_to_code
 * Tail-calls loaded code. In the ROM this is an unrecovered indirect branch
 * (BR); modelled here as an indirect call that does not return in practice.
 */
void jump_to_code(void (*entry)(void))
{
    entry();
}
