/* SPDX-License-Identifier: GPL-2.0 */
/*
 * storage_spi.c - SPI serial-flash boot driver (controller @ 0xff190000).
 *
 * Supports SPI-NOR (read command 0x03) and SPI-NAND (page-read 0x13 ->
 * get-feature 0x0f -> read-from-cache 0x03). Probing issues JEDEC RDID (0x9f)
 * and classifies the device in g_flash_type (0=NOR, 1=NAND, 2=absent).
 *
 * Behaviour-preserving reconstruction from Ghidra decompiler output.
 */
#include "bootrom.h"

#define SPI_REG_CTRL0   0xff190008u   /* DAT_ffff4a74 : enable                  */
#define SPI_REG_CS      0xff19000cu   /* DAT_ffff4a78 : chip-select             */
#define SPI_REG_TXD     0xff190400u   /* DAT_ffff4a7c : TX data                 */
#define SPI_REG_SR      0xff190024u   /* DAT_ffff4a80 : status (bit3 busy)      */
#define SPI_REG_RXD     0xff190800u   /* DAT_ffff4a84 : RX data                 */

/*
 * ffff1c80 - spi_xfer
 * Clocks out 'txlen' command words, then clocks in up to 'rxlen' bytes while
 * shifting out 0xff. Returns 0 on success, 1 on timeout.
 */
int spi_xfer(const uint32_t *tx, int txlen, uint8_t *rx, uint32_t rxlen)
{
    uint32_t left = rxlen;
    int rc = 0;

    write32(SPI_REG_CTRL0, 1);
    write32(SPI_REG_CS, 1);

    for (;;) {
        if (txlen == 0) {
            if (left == 0) { rc = 0; break; }
            write32(SPI_REG_TXD, 0xff);         /* dummy byte to clock in RX */
            left--;
        } else {
            write32(SPI_REG_TXD, *tx++);
            txlen--;
        }

        uint32_t spins = 0;
        while ((read32(SPI_REG_SR) >> 3) & 1) { /* wait not-busy */
            rc = 1;
            rom_delay(1);
            if (++spins > 1) goto done;
        }
        if (left < rxlen && rx)                 /* capture a received byte */
            *rx++ = (uint8_t)read32(SPI_REG_RXD);
        rc = 1;
    }
done:
    write32(SPI_REG_CS, 0);
    write32(SPI_REG_CTRL0, 0);
    rom_delay(0x82);
    return rc;
}

/* Shared pin-mux / clock setup used by both probes (from spiflash_probe). */
static void spi_pads_init(void)
{
    write32(0xff440160, 0xff190010);   /* CRU: ungate SPI (DAT_ffff4a48->4a4c) */
    write32(0xff190010, 2);
    write32(0xff190000, 0x24c1);       /* SPI control                          */
    write32(0xff100130, 0x00300010);   /* GRF iomux (DAT_ffff4a54)             */
    write32(0xff100038, 0x01ff0124);   /* GRF (DAT_ffff4a5c)                   */
    write32(0xff100040, 0x00070003);   /* GRF (DAT_ffff4a64)                   */
    write32(0xff100050, 0x00300020);   /* GRF (DAT_ffff4a6c)                   */
    rom_delay(1);
}

/* Validate a 3-byte JEDEC ID is neither all-0x00 nor all-0xff. */
static int jedec_id_valid(uint8_t b1, uint8_t b2)
{
    if (b1 == 0x00) return b2 != 0x00;
    if (b1 == 0xff) return !(b2 == 0xff);
    return 1;
}

/*
 * ffff1a9c - spiflash_probe
 * Brings up pads, issues RDID, and classifies NOR vs. (addr-width) from the ID.
 * Returns 0 on success (device present), 1 otherwise.
 */
int spiflash_probe(void)
{
    uint8_t id[3];
    uint32_t cmd;
    int rc = 1;

    spi_pads_init();
    g_flash_type = 2;

    cmd = 0x9f;                                 /* RDID */
    if (spi_xfer(&cmd, 1, id, 3) == 0) {
        if (!jedec_id_valid(id[0], id[1]))
            return 1;
        rc = 0;
        g_flash_type = (id[2] == 0xff);         /* addressing/type selector */
    }
    return rc;
}

/*
 * ffff1bc0 - spiflash_probe_alt
 * Secondary probe (runs when g_flash_type > 1): soft-reset (0xff), re-read the
 * JEDEC ID, and mark the device as SPI-NAND (g_flash_type = 1).
 */
int spiflash_probe_alt(void)
{
    uint8_t id[3];
    uint32_t cmd;
    int rc = 1;

    if (g_flash_type <= 1)
        return 1;

    cmd = 0xff;                                 /* reset */
    spi_xfer(&cmd, 1, 0, 0);
    rom_delay_ms(2);

    cmd = 0x9f;
    if (spi_xfer(&cmd, 1, id, 3) == 0) {
        if (!jedec_id_valid(id[0], id[1]))
            return 1;
        rc = 0;
        g_flash_type = 1;
    }
    return rc;
}

/*
 * ffff1da4 - flash_read_sector
 * Reads 'len' bytes at linear address 'lba' into 'buf'. NOR uses a single
 * 0x03 read; NAND issues page-load (0x13), polls the feature register (0x0f)
 * for ready, then reads from cache (0x03). Returns 0 on success.
 */
int flash_read_sector(uint32_t lba, void *buf, uint32_t len)
{
    uint32_t cmd[6];
    int clen;
    int rc = 1;

    if (g_flash_type >= 2)
        return 1;

    if (g_flash_type == 0) {                    /* SPI-NOR: READ 0x03 + 3B addr */
        cmd[0] = 0x03;
        cmd[1] = (lba >> 7) & 0xff;
        cmd[2] = (lba & 0x7f) << 1;
        cmd[3] = 0;
        clen = 4;
        rc = spi_xfer(cmd, clen, buf, len);
    } else {                                    /* SPI-NAND */
        cmd[0] = 0x13;                          /* PAGE READ to cache */
        cmd[1] = (lba >> 0x12) & 0x1f;
        cmd[2] = (lba >> 0x0a) & 0xff;
        cmd[3] = (lba >> 0x02) & 0xff;
        if (spi_xfer(cmd, 4, 0, 0) == 0) {
            uint8_t feat;
            for (uint32_t i = 0; i < 0x14; i++) {
                cmd[0] = 0x0f; cmd[1] = 0xc0;   /* GET FEATURE (status) */
                if (spi_xfer(cmd, 2, &feat, 1) != 0)
                    return 1;
                if ((feat & 1) == 0) {          /* OIP clear -> ready */
                    cmd[0] = 0x03;              /* READ FROM CACHE */
                    cmd[1] = (lba & 3) << 1;
                    rom_memset(&cmd[2], 0, 0x18);
                    clen = (int)((g_nand_addr_shift >> 3) + 3);
                    return spi_xfer(cmd, clen, buf, len);
                }
            }
            g_flash_type = 2;                   /* never became ready */
        }
    }
    return rc;
}

/*
 * ffff1f08 - flash_read_image
 * Reads an image of size encoded in 'size_field' (sectors in bits [31:9]) into
 * 'buf', one 0x800-byte chunk per iteration.
 */
int flash_read_image(int dst, uintptr_t buf, uint64_t size_field)
{
    uint32_t sectors = (uint32_t)(size_field >> 9) & 0x7fffff;
    int rc = 1;

    if (sectors != 0) {
        for (uint32_t i = 0; i < sectors; i += 4) {
            rc = flash_read_sector((uint32_t)(dst + i), (void *)buf, 0x800);
            if (rc != 0)
                return rc;
            buf += 0x800;
        }
        rc = 0;
    }
    return rc;
}

/*
 * ffff1f70 - flash_find_idb
 * Reads a sector and scans the first 0x1d entries (8-byte stride) for the IDB
 * sector-0 magic (0xfcdc8c3b, little-endian bytes 3b 8c dc fc). On a hit it
 * reads a full 0x200 block and reports the found LBA via *found_lba.
 * Returns 0 if found & loaded, 1 otherwise.
 */
int flash_find_idb(uint32_t idx, uintptr_t buf, int *found_lba)
{
    g_nand_addr_shift = 0;
    int lba = (int)((1u << (idx & 0x1f) & 0x3ffffffeu) << 2);

    if (flash_read_sector(lba, (void *)buf, 0x20) != 0)
        return 1;

    const uint8_t *p = (const uint8_t *)buf;
    uint32_t cnt = 0, offs = 0;
    for (cnt = 0; cnt < 0x1d; cnt++) {
        if (p[0] == 0x3b && p[1] == 0x8c && p[2] == 0xdc && p[3] == 0xfc) {
            if (cnt > 0x1c) { g_nand_addr_shift = offs; return 1; }
            g_nand_addr_shift = offs;
            if (flash_read_sector(lba, (void *)buf, 0x200) != 0)
                return 1;
            *found_lba = lba;
            return 0;
        }
        offs += 8;
        p++;
    }
    return 1;
}
