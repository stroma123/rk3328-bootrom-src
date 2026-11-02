/* SPDX-License-Identifier: GPL-2.0 */
/*
 * rk3328_regs.h - MMIO register map for the RK3328 mask BootROM
 *
 * Reconstructed by static analysis of bootrom.elf (AArch64, image base
 * 0xffff0000) using Ghidra. Every base/offset below was derived from the
 * literal constant pool embedded in the ROM (addresses 0xffff48e0..0xffff4c6c)
 * and from the access patterns in the decompiled code.
 *
 * Peripheral *base* addresses are well established for the RK3328 SoC. Register
 * *offsets* and bit meanings marked "UNCERTAIN" were inferred only from usage
 * and should be treated as hypotheses, not datasheet facts.
 *
 * NOTHING here is guessed beyond what the binary demonstrably touches.
 */
#ifndef RK3328_REGS_H
#define RK3328_REGS_H

#include <stdint.h>

/* ---- Generic 32-bit MMIO accessors ------------------------------------- */
#define MMIO32(addr)        (*(volatile uint32_t *)(uintptr_t)(addr))
#define MMIO16(addr)        (*(volatile uint16_t *)(uintptr_t)(addr))
#define MMIO8(addr)         (*(volatile uint8_t  *)(uintptr_t)(addr))

static inline uint32_t read32(uintptr_t a)            { return MMIO32(a); }
static inline void     write32(uintptr_t a, uint32_t v){ MMIO32(a) = v;   }
static inline void     setbits32(uintptr_t a, uint32_t m){ MMIO32(a) |= m; }
static inline void     clrbits32(uintptr_t a, uint32_t m){ MMIO32(a) &= ~m; }

/* ---- Peripheral bases (confirmed against access patterns) -------------- */
#define CRYPTO_BASE     0xff060000u  /* Security/crypto engine: SHA-256 + RSA  */
#define SGRF_SEC_BASE   0xff090000u  /* On-chip SRAM scratch / BootROM state   */
#define OTP_BASE        0xff0a0000u  /* OTP_S  - secure OTP (two read protocols) */
#define EFUSE_BASE      0xff0b0000u  /* EFUSE_S - secure eFuse controller        */
#define SGRF_BASE       0xff0d0000u  /* Secure GRF (write-enable mask regs)     */
#define GRF_BASE        0xff100000u  /* General register file                   */
#define SPI_BASE        0xff190000u  /* SPI master (serial NOR/NAND flash)      */
#define CLK_GATE2300    0xff230000u  /* Clock/soft-reset bit used by OTP path   */
#define CRU_BASE        0xff440000u  /* Clock & Reset Unit (PLLs, gates, resets)*/
#define SDMMC0_BASE     0xff500000u  /* DW-MMC host 0 (SD card)                 */
#define SDMMC1_BASE     0xff520000u  /* DW-MMC host 1 (eMMC)                    */
#define USB_OTG_BASE    0xff580000u  /* DWC2 USB-OTG controller (maskrom mode)  */

/* ---- Crypto engine (0xff060000) ---------------------------------------- *
 * Offsets taken from the constant pool (DAT_ffff48e0 block). "RK32" magic
 * (0x32334b52) at 0xffff48e0 tags this table in the ROM.
 */
#define CRYPTO_CTRL         (CRYPTO_BASE + 0x0000) /* global enable / DMA ctrl   */
#define CRYPTO_INTSTS       (CRYPTO_BASE + 0x0008) /* status bits               */
#define CRYPTO_CONF         (CRYPTO_BASE + 0x000c) /* config (hash/rsa select)  */
#define CRYPTO_HASH_CTRL    (CRYPTO_BASE + 0x0180) /* hash enable (UNCERTAIN)    */
#define CRYPTO_HASH_MSGLEN  (CRYPTO_BASE + 0x0188) /* message length            */
#define CRYPTO_HRDMA_ADDR   (CRYPTO_BASE + 0x0188) /* hash source DMA addr       */
#define CRYPTO_HRDMA_LEN    (CRYPTO_BASE + 0x018c) /* hash source DMA word count */
#define CRYPTO_HASH_DOUT    (CRYPTO_BASE + 0x0400) /* 8x32 SHA-256 digest out    */
#define CRYPTO_RSA_M        (CRYPTO_BASE + 0x0400) /* RSA operand banks (UNCERTAIN)*/
#define CRYPTO_RSA_N        (CRYPTO_BASE + 0x0500)
#define CRYPTO_RSA_C        (CRYPTO_BASE + 0x0600)
#define CRYPTO_RSA_RESULT   (CRYPTO_BASE + 0x0700)

/* ---- secure eFuse (EFUSE_S, 0xff0b0000) -------------------------------- */
#define EFUSE_PWR           (EFUSE_BASE + 0x0000)  /* clock/power enable bits      */
#define EFUSE_PROG_CMD      (EFUSE_BASE + 0x0010)  /* program command (UNCERTAIN)  */
#define EFUSE_CMD           (EFUSE_BASE + 0x001c)  /* read command / row address   */
#define EFUSE_DATA          (EFUSE_BASE + 0x0020)  /* read data word               */
#define EFUSE_MASK_EN       (SGRF_BASE + 0x0014) /* eFuse write-enable mask (SGRF)*/

/* ---- SPI master (0xff190000) ------------------------------------------- */
#define SPI_CTRLR0          (SPI_BASE + 0x0008)  /* enable/control (UNCERTAIN)   */
#define SPI_CS              (SPI_BASE + 0x000c)  /* chip-select                  */
#define SPI_TXDR            (SPI_BASE + 0x0400)  /* TX data                      */
#define SPI_SR              (SPI_BASE + 0x0024)  /* status (bit3 = busy)         */
#define SPI_RXDR            (SPI_BASE + 0x0800)  /* RX data                      */

/*
 * DW-MMC host register offsets (relative to SDMMC0_BASE / SDMMC1_BASE), as used
 * by mmc_transfer()/mmc_wait_cmd_done(). These line up with the Synopsys
 * DesignWare MMC block that Rockchip uses.
 */
#define DWMMC_CTRL          0x0000
#define DWMMC_CLKENA        0x0010
#define DWMMC_TMOUT         0x0014
#define DWMMC_CTYPE         0x0018
#define DWMMC_BLKSIZ        0x001c
#define DWMMC_BYTCNT        0x0020
#define DWMMC_INTMASK       0x0024
#define DWMMC_CMDARG        0x0028
#define DWMMC_CMD           0x002c
#define DWMMC_RESP0         0x0030
#define DWMMC_RINTSTS       0x0044
#define DWMMC_STATUS        0x0048
#define DWMMC_FIFO_NORMAL   0xff500200u   /* host0 FIFO window (DAT_ffff4ac8)    */
#define DWMMC_FIFO_HOST1    0xff520200u   /* host1 FIFO window (DAT_ffff4ac4)    */

/* ---- Misc confirmed registers ------------------------------------------ */
#define CLK2300_REG0        (CLK_GATE2300 + 0x0000) /* _DAT_ff230000, bit3        */

#endif /* RK3328_REGS_H */
