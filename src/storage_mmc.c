/* SPDX-License-Identifier: GPL-2.0 */
/*
 * storage_mmc.c - DesignWare MMC (DW-MMC) boot driver.
 *
 * Two host instances: host 0 @ 0xff500000 (SD card), host 1 @ 0xff520000
 * (eMMC). The ROM talks raw CMD/arg/response + PIO FIFO. Command values such
 * as 0x2351 pack the SD/MMC command index with DW-MMC CMD-register flags
 * (start_cmd | response_expect | data | ...). They are preserved verbatim.
 *
 * Behaviour-preserving reconstruction from Ghidra decompiler output.
 */
#include "bootrom.h"

#define HOST_BASE(h)    ((uintptr_t)((h) ? SDMMC1_BASE : SDMMC0_BASE))
#define HOST_FIFO(h)    ((uintptr_t)((h) ? DWMMC_FIFO_HOST1 : DWMMC_FIFO_NORMAL))

/* DW-MMC register offsets (see rk3328_regs.h for the shared set). */
#define CTRL        0x00
#define CLKENA      0x10
#define CTYPE       0x18
#define BLKSIZ      0x1c
#define BYTCNT      0x20
#define CMDARG      0x28
#define CMD         0x2c
#define RESP0       0x30
#define RINTSTS     0x44
#define STATUS      0x48

/*
 * ffff2548 - mmc_wait_cmd_done
 * Writes a command value to the CMD register and waits for the start bit
 * (bit 31) to self-clear. Returns 0 on success, 0x1000 on timeout.
 */
int mmc_wait_cmd_done(uintptr_t host, uint32_t cmdval)
{
    int budget = 1000;
    write32(host + CMD, cmdval);
    if (read32(host + CMD) >= 0x80000000u) {
        do {
            if (budget-- < 1) break;
            rom_delay(1);
        } while ((int)read32(host + CMD) < 0);
    }
    return budget != 0 ? 0 : 0x1000;
}

/*
 * ffff27e8 - mmc_reset_fifo
 * Issues the FIFO reset (CTRL bit1) unless the DMA is busy, and waits for it
 * to clear.
 */
void mmc_reset_fifo(uint32_t *host)
{
    if ((host[STATUS / 4] >> 2 & 1) == 0) {
        host[0] |= 2;
        for (int i = 5000; i > 0; i--)
            if ((host[0] >> 1 & 1) == 0)
                return;
    }
}

/*
 * ffff25bc - mmc_transfer
 * Core command+data engine. Sends CMD/arg, optionally programs a data transfer
 * (block size/count), waits for completion, reads the response and (for read
 * commands) drains the PIO FIFO into 'buf'. Return value encodes the error
 * class (0 = success), matching the ROM's status words.
 */
int mmc_transfer(int host, uint32_t cmd, uint32_t arg, uint32_t *resp,
                 uint32_t blksz, uint32_t len, uint32_t *buf)
{
    uintptr_t b = HOST_BASE(host);
    uintptr_t fifo = HOST_FIFO(host);
    uint32_t ret = 0;

    if (((cmd >> 0xd & 1) && (read32(b + STATUS) >> 9 & 1)) ||
        ((int)read32(b + CMD) >= 0)) {
        /* data-busy / card-busy guard failed */
        if (cmd >> 0xd & 1) return 0x400;
        return 0x1000;
    }

    mmc_reset_fifo((uint32_t *)b);

    if (cmd >> 9 & 1) {                      /* data command: program size */
        write32(b + BLKSIZ, blksz);
        write32(b + BYTCNT, len);
    }
    write32(b + CMDARG, arg);

    if (mmc_wait_cmd_done(b, (cmd & 0x5ffeffff) | 0xa0000000) != 0)
        return ret;

    for (int t = 1000; (read32(b + RINTSTS) >> 2 & 1) == 0 && t > 0; t--)
        rom_delay(1);
    write32(b + RINTSTS, 4);

    if (cmd >> 0xe & 1)
        mmc_reset_fifo((uint32_t *)b);

    if (read32(b + RINTSTS) >> 8 & 1) {     /* response/CRC error */
        write32(b + RINTSTS, 0xffffffff);
        return 0x20;
    }

    if (cmd & 0x200) {                      /* data read phase */
        uint32_t words = len >> 2;
        int t = 0;
        while (words) {
            if (read32(b + RINTSTS) & 0xa280) break;   /* data error */
            if ((read32(b + STATUS) >> 2 & 1) == 0) {  /* FIFO not empty */
                while (words) {
                    *buf++ = read32(fifo);
                    words--;
                    if (read32(b + STATUS) >> 2 & 1) break;
                }
                if (words == 0) {
                    if ((read32(b + RINTSTS) & 0xa280) == 0) break;
                }
            }
            rom_delay(1);
            if (t++ >= 0x186a1 /* DAT_ffff4acc = 100001 */) break;
        }
        write32(b + RINTSTS, 0xffffffff);
        ret = 0x800000;
    } else {
        write32(b + RINTSTS, 0xffffffff);
        if (cmd >> 0x10 & 1) {              /* wait for data-busy to clear */
            for (int t = 0; read32(b + STATUS) >> 9 & 1; t++) {
                rom_delay(1);
                if (t >= 0x3d091 /* DAT_ffff4ad0 = 250001 */) { ret = 0x400; break; }
            }
        }
        if ((cmd >> 6 & 1) && resp)
            *resp = read32(b + RESP0);
    }
    return ret;
}

/*
 * ffff282c - mmc_send_cmd
 * Convenience wrapper: command with no data phase.
 */
int mmc_send_cmd(int host, uint32_t cmd, uint32_t arg, uint32_t *resp)
{
    return mmc_transfer(host, cmd, arg, resp, 0, 0, 0);
}

/*
 * ffff23ec - mmc_wait_ready_cmd
 * Sends CMD13 (0x2177 SEND_STATUS); if the card reports "ready for data"
 * (bit 5) it forwards the real command, otherwise returns success with no-op.
 */
int mmc_wait_ready_cmd(int host, uint32_t cmd, uint32_t arg, uint32_t *resp)
{
    uint32_t st = 0;
    int rc = mmc_send_cmd(host, 0x2177, (uint32_t)g_mmc_card_type << 16, &st);
    if (rc == 0) {
        if ((st >> 5) & 1)
            rc = mmc_send_cmd(host, cmd, arg, resp);
        else
            rc = 0;
    }
    return rc;
}

/*
 * ffff249c - mmc_set_bus_width
 * CMD6/ACMD6 style bus-width/clock reprogram via the host CLKENA path.
 */
int mmc_set_bus_width(int host)
{
    uintptr_t b = HOST_BASE(host);
    write32(b + CLKENA, 0);
    if (mmc_wait_cmd_done(b, 0xff811104 /* DAT_ffff4ab4 */) != 0)
        return 0x1000;
    /* program CRU/host clock divider (addresses differ per host) */
    write32(host ? 0xff440180 : 0xff440178, 0xc0008000 /* DAT_ffff4ab8 */);
    write32(b + CTYPE, 0);
    write32(b + CLKENA, 1);
    return mmc_wait_cmd_done(b, 0xff811104) ? 0x1000 : 0;
}

/*
 * ffff283c - mmc_host_init
 * Powers and clocks the selected DW-MMC host (mode 3 = eMMC on host1-style
 * path, mode 0 = SD on host0), resets the controller and configures the clock.
 */
int mmc_host_init(int mode)
{
    volatile uint32_t *h = (volatile uint32_t *)(uintptr_t)SDMMC0_BASE;

    if (mode == 0) {
        write32(0xff440178, 0x3fff2aaa);    /* CRU softrst (DAT_ffff4ad4)       */
        write32(0xff100048, 0x3fff1555);    /* GRF iomux  (DAT_ffff4af4)        */
        write32(0xff100010, 0x80202000);    /* GRF        (DAT_ffff4afc)        */
        write32(0xff10000c, 2);
    } else {
        h = (volatile uint32_t *)(uintptr_t)SDMMC1_BASE;
        write32(0xff440180, 0x3fff2aaa);    /* DAT_ffff4ad4 at 0xff440180       */
        write32(0xff100000, 0xc0008000);    /* _DAT_ff100000 (DAT_ffff4adc)     */
        write32(0xff1006b0, 0xff00aa00);    /* DAT_ffff4ae0 -> 4ae4             */
        write32(0xff100034, 0x3fff2aaa);    /* DAT_ffff4ae8 -> 4aec             */
    }
    rom_delay(1);
    g_mmc_host_id = mode;
    h[1] = (mode == 3);                     /* PWREN */
    rom_delay(1000);
    h[0] = 3;                               /* CTRL: reset controller+FIFO      */
    rom_delay(100);
    h[2] = 0;
    h[4] = 1;
    h[0xb] = 0x80202000;                    /* DAT_ffff4b04 : CLKDIV/CLKSRC     */
    if ((uint32_t)h[0xb] >= 0x80000000u) {
        for (int i = 9999; i > 0; i--) {
            rom_delay(1);
            if ((uint32_t)h[0xb] < 0x80000000u) break;
        }
    }
    rom_delay(500);
    h[5] = 0xffffff40;                       /* TMOUT */
    h[0x13] = 0x307f0080;                    /* DAT_ffff4b08 : UHS / card thresh */
    h[0x11] = 0xffffffff;
    return 0;
}

/*
 * ffff2054 - mmc_init_sd
 * SD card bring-up: ACMD41 (0x2041) power-up poll, then CMD2/3/9/7/16-style
 * sequence, OCR/CSD handling and bus setup. Returns 0 on success.
 */
int mmc_init_sd(int host)
{
    uint32_t cnt = 0, ocr = 0;
    uint16_t caps;

    for (;;) {
        if (mmc_send_cmd(host, 0x2041, 0x40ff8000 /* DAT_ffff4a88 */, &ocr) != 0)
            return 1;
        if ((int)ocr < 0)                    /* card ready (busy bit set) */
            break;
        cnt++;
        if ((cnt >> 6) > 0x7c) {
            caps = 0;
            goto configure;
        }
    }
    caps = 0x40;
    if ((ocr & 0xffffff7f) != 0x80ff8000u /* DAT_ffff4a8c */) {
        caps = 0x20;
        if ((ocr & 0xffffff7f) != 0xc0ff8000u /* DAT_ffff4a90 */)
            return 1;
    }

configure:
    if (cnt == 8000)
        return 0x2000;
    if (mmc_send_cmd(host, 0x21c2, 0, 0) != 0)     /* CMD2 ALL_SEND_CID */
        return 0x2000;
    g_mmc_card_type = 2;
    if (mmc_send_cmd(host, 0x2143, 0x20000, 0) != 0) /* CMD3 SEND_RCA */
        return 0;
    if (mmc_set_bus_width(host) != 0)
        return 0;
    {
        uint32_t resp = 0;
        if (mmc_send_cmd(host, 0x00012147 /* DAT_ffff4a94 CMD7 */,
                         (uint32_t)g_mmc_card_type << 16, &resp) != 0)
            return 0;
        if (mmc_send_cmd(host, 0x2150, 0x200, &resp) != 0) /* SET_BLOCKLEN */
            return 0;
    }
    {
        volatile uint32_t *h = (volatile uint32_t *)HOST_BASE(host);
        uint32_t aw; uint32_t acmd_arg;
        if (host == 3) { aw = 0x10000; acmd_arg = 0x03b70200 /* DAT_ffff4a9c */; }
        else           { aw = 1;       acmd_arg = 0x03b70100 /* DAT_ffff4a98 */; }
        h[CTYPE / 4] = aw;
        uint32_t resp = 0;
        if (mmc_send_cmd(host, 0x00012146 /* DAT_ffff4aa0 ACMD6 */, acmd_arg, &resp) == 0
            && (int8_t)resp >= 0)
            mmc_send_cmd(host, 0x14d, (uint32_t)g_mmc_card_type << 16, &resp);
    }
    g_mmc_caps = caps;
    return 0;
}

/*
 * ffff2240 - mmc_init_mmc
 * eMMC bring-up: CMD1 (0x2069 SEND_OP_COND) power-up poll with the correct OCR,
 * then CMD2/3/9/7-style setup and bus configuration.
 */
int mmc_init_mmc(int host, int kind)
{
    uint32_t cnt = 0, resp = 0;
    uint32_t ocr_arg = (kind == 1) ? 0x40ff8000u /* DAT_ffff4aa4 */ : 0x00ff8000u;
    uint16_t caps;

    for (;;) {
        if (mmc_wait_ready_cmd(host, 0x2069, ocr_arg, &resp) != 0)
            return 1;
        if ((int)resp < 0)
            break;
        cnt++;
        if (cnt > 0x7f7) { caps = 0; goto configure; }
    }
    caps = 0x10;
    if (kind == 1) {
        caps = 4;
        if ((resp & 0xffffff7f) != 0x40ff8000u /* DAT_ffff4aa8 */) {
            caps = 8;
            if ((resp & 0xffffff7f) != 0x80ff8000u /* DAT_ffff4aac */)
                caps = 0;
        }
    }

configure:
    if (cnt == 0x7f8)
        return 0x2000;
    if (mmc_send_cmd(host, 0x21c2, 0, 0) != 0) return 0x2000;      /* CMD2 */
    if (mmc_send_cmd(host, 0x2143, 0, &resp) != 0) return 0x2000;  /* CMD3 */
    g_mmc_card_type = (uint16_t)(resp >> 16);
    if (mmc_set_bus_width(host) != 0) return 0x2000;
    if (mmc_send_cmd(host, 0x00012147 /* CMD7 DAT_ffff4ab0 */,
                     (uint32_t)g_mmc_card_type << 16, 0) != 0) return 0x2000;
    if (mmc_send_cmd(host, 0x2150, 0x200, 0) != 0) return 0x2000;  /* SET_BLOCKLEN */
    if (mmc_wait_ready_cmd(host, 0x216a, 0, 0) != 0) return 0x2000;
    if (mmc_wait_ready_cmd(host, 0x2146, 2, 0) == 0) {
        volatile uint32_t *h = (volatile uint32_t *)HOST_BASE(host);
        h[CTYPE / 4] = 1;
    }
    g_mmc_caps = caps;
    return 0;
}

/*
 * ffff29b0 - mmc_card_init
 * Card identification dispatcher: CMD0 (GO_IDLE), CMD8 (SEND_IF_COND 0x1aa),
 * then SD (mmc_init_sd) or MMC (mmc_init_mmc) depending on the response.
 */
int mmc_card_init(int host)
{
    int r;
    g_mmc_card_type = 0;
    g_mmc_caps = 0;

    r = mmc_send_cmd(host, 0x8100, 0, 0);          /* CMD0 GO_IDLE_STATE */
    if (r != 0) return r;
    rom_delay(100);

    r = mmc_send_cmd(host, 0x2148, 0x1aa, 0);      /* CMD8 SEND_IF_COND */
    if (r == 0x20) {
        r = mmc_send_cmd(host, 0x2177, 0, 0);      /* CMD55 APP_CMD */
        if (r == 0x20)
            return mmc_init_sd(host);
        if (r != 0) return 1;
        r = 0;
    } else {
        if (r != 0) return 1;
        r = 1;
    }
    return mmc_init_mmc(host, r);
}

/*
 * ffff2a78 - mmc_read_blocks  (driver read entry, offset +8)
 * Reads 'len' bytes at block 'lba' using CMD17/CMD18 (0x2351/0x2352), issuing
 * CMD12 STOP after a multi-block read.
 */
int mmc_read_blocks(int lba, uintptr_t buf, uint32_t len)
{
    uint32_t sh = ((g_mmc_caps & 0x24) == 0) ? 9 : 0;   /* byte vs block addr */
    uint32_t cmd = (len < 0x201) ? 0x2351 : 0x2352;
    uint32_t rc = mmc_transfer(g_mmc_host_id, cmd, (uint32_t)lba << sh,
                               0, 0x200, len, (uint32_t *)buf);
    if (len > 0x200 && (rc & 0xff7fffff) == 0)
        mmc_send_cmd(g_mmc_host_id, 0x0001414c /* CMD12 DAT_ffff4b0c */, 0, 0);
    return rc != 0;
}

/*
 * ffff2b24 - mmc_read_block_lba  (driver read entry, offset +0x10)
 * Single-block read returning the computed controller address.
 */
int mmc_read_block_lba(int lba, uintptr_t buf, uint32_t *out_addr)
{
    uint32_t a = ((uint32_t)lba << 10) | 0x40;
    uint32_t sh = ((g_mmc_caps & 0x24) == 0) ? 9 : 0;
    int rc = mmc_transfer(g_mmc_host_id, 0x2351, a << sh, 0, 0x200, 0x200,
                          (uint32_t *)buf);
    if (rc == 0) { *out_addr = a; return 0; }
    return -1;
}

/*
 * ffff220c - emmc_probe  (driver probe, host 3 path)
 */
int emmc_probe(void)
{
    mmc_host_init(3);
    return mmc_card_init(3) != 0;
}

/*
 * ffff2468 - sd_probe  (driver probe, host 0 path)
 */
int sd_probe(void)
{
    mmc_host_init(0);
    return mmc_card_init(0) != 0;
}
