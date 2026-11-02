/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bootrom.h - shared declarations for the reconstructed RK3328 BootROM
 *
 * Function names are RECONSTRUCTED. Each prototype carries the original ROM
 * address so the mapping back to the binary is never lost. Where the exact
 * C-level type could not be established from the decompiler, parameters are
 * left as uintptr_t / uint32_t and annotated.
 */
#ifndef BOOTROM_H
#define BOOTROM_H

#include <stdint.h>
#include <stddef.h>
#include "rk3328_regs.h"

/* =======================================================================
 *  On-chip SRAM scratch / BootROM state block @ 0xff090000
 *  ----------------------------------------------------------------------
 *  The ROM keeps all of its mutable state in SRAM at 0xff090000. The field
 *  offsets below are exactly those dereferenced by the code (_DAT_ff09xxxx).
 *  Names are reconstructed; offsets are authoritative.
 * ======================================================================= */
#define SRAM_STATE_BASE     0xff090000u

#define g_timer_clock_mhz   MMIO32(0xff090000) /* udelay reference clock (24/200/400) */
#define g_secure_boot       MMIO32(0xff09000c) /* 1 = secure boot enforced            */
#define g_boot_stage        MMIO32(0xff090010) /* boot-source id (from driver->param)  */
#define g_idb_src_addr      MMIO32(0xff090014) /* LBA/offset where the IDB was found   */
#define g_otp_present     MMIO32(0xff090018) /* OTP controller detected (otp_init)  */
#define g_efuse_prog_mode     MMIO32(0xff09001c) /* eFuse program width selector        */
#define g_efuse_prog_cnt      MMIO32(0xff090020) /* eFuse program bit budget            */
#define g_efuse_prog_max      MMIO32(0xff090024)
#define g_efuse_prog_valid    MMIO8 (0xff090028)
#define g_key_words         MMIO32(0xff09002c) /* OTP-stored key length in words      */
#define g_flash_type        MMIO32(0xff090030) /* 0=SPI-NOR 1=SPI-NAND 2=none/MMC     */
#define g_nand_addr_shift   MMIO32(0xff090034)
#define g_sig_ok            MMIO8 (0xff090038) /* running signature-chain OK flag     */
/* 0xff09003c : 0x44-byte signature/key context (SHA + RSA params)           */
/* 0xff090060 : second 0x44-byte signature context                          */
#define g_usb_ep0_maxpkt    MMIO16(0xff090080)
/* 0xff090084 : 8-byte USB SETUP packet                                     */
#define g_usb_setup_bmreq   MMIO8 (0xff090084)
#define g_usb_setup_brequest MMIO8(0xff090085)
#define g_usb_dev_addr      MMIO8 (0xff090086)
#define g_usb_desc_type     MMIO8 (0xff090087)
#define g_usb_download_tag  MMIO16(0xff090088) /* 0x471 / 0x472 rockusb tags           */
#define g_usb_wlength       MMIO16(0xff09008a)
#define g_usb_rx_off        MMIO32(0xff09008c)
#define g_usb_load_addr     MMIO32(0xff090090) /* 64-bit download destination          */
#define g_usb_remaining     MMIO16(0xff090098)
#define g_usb_state         MMIO8 (0xff09009c)
#define g_usb_databuf       MMIO32(0xff0900a0) /* control-xfer data pointer            */
#define g_usb_bulk_maxpkt   MMIO16(0xff0900e8)
#define g_otp_variant      MMIO32(0xff0900ec) /* selects otp_read_proto_a vs _b      */
#define RC4_SBOX            0xff0900f0u         /* 256-byte RC4 state                   */
#define IDB_LOAD_BUF        0xff091000u         /* sector staging buffer                */
#define g_mmc_card_type     MMIO16(0xff0901f0)
#define g_mmc_caps          MMIO16(0xff0901f2)
#define g_usb_download_done MMIO8 (0xff0901f4)
#define g_mmc_host_id       MMIO32(0xff0901f8)

/* =======================================================================
 *  ROM magic constants (from the literal pool)
 * ======================================================================= */
#define MAGIC_RSAK          0x4b415352u  /* "RSAK" - signed-header tag (ffff073c/0740) */
#define MAGIC_RK32          0x32334b52u  /* "RK32" - code-section end tag (ffff48e0)   */
#define MAGIC_IDB_SECTOR0   0xfcdc8c3bu  /* IDB first-sector magic (ffff4b10)          */
#define RKUSB_TAG_DRAM      0x0471       /* download DRAM-init blob                    */
#define RKUSB_TAG_LOADER    0x0472       /* download loader blob                       */

/* =======================================================================
 *  Function prototypes  (name  <-  original ROM address)
 * ======================================================================= */

/* --- util.c ------------------------------------------------------------- */
void      rom_delay(int units);                               /* ffff06b0 */
void      rom_delay_ms(int n);                                /* ffff0704 */
void      delay_spin(void);                                   /* ffff45d8 */
uint32_t  get_timer_clock(void);                              /* ffff0698 */
void      set_timer_clock(uint32_t mhz);                      /* ffff06a4 */
int       rom_memcmp(const void *a, const void *b, size_t n); /* ffff42c4 */
void     *rom_memcpy(void *d, const void *s, size_t n);       /* ffff4480 */
void     *rom_memset(void *d, int c, size_t n);               /* ffff43c8 */
uint16_t  crc16_ccitt(const uint8_t *buf, int len);           /* ffff3f0c */
uint64_t  cpu_enable_irq_abort(void);                         /* ffff45e4 */
void      jump_to_code(void (*entry)(void));                  /* ffff45f8 */

/* --- efuse.c (secure eFuse @ 0xff0b0000) ------------------------------- */
int       efuse_read(void *dst, int row, int count);           /* ffff3fe4 */
int       efuse_program_bits(uint32_t row, uint32_t mask);     /* ffff40b8 */
int       efuse_write_verify(uint32_t row, uint32_t mask);     /* ffff4204 */
int       efuse_count_bits(int field_count, uint32_t *out);    /* ffff0138 */
int       efuse_program_from_desc(void);                       /* ffff01e0 */

/* --- otp.c (secure OTP @ 0xff0a0000) ----------------------------------- */
void      otp_init(void);                                  /* ffff159c */
int       otp_read(void *dst, int addr_words, uint32_t nwords); /* ffff156c */
int       otp_read_proto_a(uint32_t *dst, int addr, uint32_t n);/* ffff10ac */
int       otp_read_proto_b(uint32_t *dst, int addr, uint32_t n);/* ffff13ac */

/* --- crypto.c ----------------------------------------------------------- */
int       sha_start(uint32_t msg_len);                       /* ffff0b84 */
int       sha_update_dma(const void *addr, int len);         /* ffff0bd4 */
int       sha_read_digest(void *out32);                      /* ffff0c20 */
int       sha_final_compare(const void *expected32);         /* ffff0c68 */
int       crypto_copy_bigint(uintptr_t dst_reg, const void *src, int n); /* ffff439c */
int       rsa_load_operands(const void *a, const void *b,
                            const void *c, const void *d);    /* ffff0cd0 */
int       rsa_load_and_run(const void *a, const void *b,
                           const void *c, const void *d);     /* ffff0db4 */
int       rsa_read_result_cmp(void);                         /* ffff0ebc */
int       rsa_verify_signature(const void *hdr, int len);    /* ffff0fb0 */
void      rc4_crypt(uint8_t *buf, int len);                  /* ffff3f60 */
void      crypto_clk_enable(void);                           /* ffff1084 */

/* --- secure_boot.c ------------------------------------------------------ */
int       secure_boot_header_verify(const void *hdr);        /* ffff02bc */
int       read_security_config(void);                        /* ffff04b8 */

/* --- clock.c ------------------------------------------------------------ */
void      cru_early_init(void);                              /* ffff18d4 */
void      cru_pll_init(void);                                /* ffff194c */

/* --- storage_spi.c ------------------------------------------------------ */
int       spiflash_probe(void);                              /* ffff1a9c */
int       spiflash_probe_alt(void);                          /* ffff1bc0 */
int       spi_xfer(const uint32_t *tx, int txlen,
                   uint8_t *rx, uint32_t rxlen);             /* ffff1c80 */
int       flash_read_sector(uint32_t lba, void *buf, uint32_t len); /* ffff1da4 */
int       flash_read_image(int dst, uintptr_t buf, uint64_t size_field); /* ffff1f08 */
int       flash_find_idb(uint32_t idx, uintptr_t buf, int *found_lba);   /* ffff1f70 */

/* --- storage_mmc.c ------------------------------------------------------ */
int       emmc_probe(void);                                  /* ffff220c */
int       sd_probe(void);                                    /* ffff2468 */
int       mmc_host_init(int host);                           /* ffff283c */
int       mmc_card_init(int host);                           /* ffff29b0 */
int       mmc_init_sd(int host);                             /* ffff2054 */
int       mmc_init_mmc(int host, int kind);                  /* ffff2240 */
int       mmc_send_cmd(int host, uint32_t cmd, uint32_t arg, uint32_t *resp); /* ffff282c */
int       mmc_transfer(int host, uint32_t cmd, uint32_t arg, uint32_t *resp,
                       uint32_t blksz, uint32_t len, uint32_t *buf);          /* ffff25bc */
int       mmc_wait_cmd_done(uintptr_t host, uint32_t cmdval); /* ffff2548 */
int       mmc_set_bus_width(int host);                       /* ffff249c */
void      mmc_reset_fifo(uint32_t *host);                    /* ffff27e8 */
int       mmc_wait_ready_cmd(int host, uint32_t cmd, uint32_t arg, uint32_t *resp); /* ffff23ec */
int       mmc_read_blocks(int lba, uintptr_t buf, uint32_t len); /* ffff2a78 */
int       mmc_read_block_lba(int lba, uintptr_t buf, uint32_t *out_addr); /* ffff2b24 */

/* --- boot.c ------------------------------------------------------------- */
void      boot_try_devices(void);                            /* ffff2e68 */
void      boot_load_image(uintptr_t driver);                 /* ffff2ba0 */
void      bootrom_main(void);                                /* ffff4288 */

/* --- usb.c -------------------------------------------------------------- */
void      usb_maskrom_mode(void);                            /* ffff3ed8 */
void      usb_otg_init(void);                                /* ffff3dfc */
void      usb_core_init(void);                               /* ffff30b4 */
void      usb_bus_reset(void);                               /* ffff3398 */
void      usb_phy_reset(void);                               /* ffff3054 */
void      usb_set_speed(void);                               /* ffff3658 */
void      gic_irq_handler(void);                             /* ffff3434 */
void      usb_isr(void);                                     /* ffff3474 */
void      usb_ep_dispatch(void);                             /* ffff355c */
void      usb_handle_gintsts(void);                          /* ffff3708 */
void      usb_handle_ep_ints(void);                          /* ffff3780 */
void      usb_handle_setup(void);                            /* ffff3aa8 */
void      usb_parse_control_request(void);                   /* ffff3ad0 */
void      usb_rx_data_pump(uint64_t count);                  /* ffff3858 */
void      usb_download_handler(uintptr_t pkt);               /* ffff3c2c */
int       usb_blob_decode(uintptr_t buf, int len);           /* ffff3e6c */
void      usb_ep_tx(uint32_t len, const uint32_t *buf);      /* ffff32f4 */
void      usb_ep_rx(uint32_t len, void *buf);                /* ffff32b0 */
void      gic_enable_usb_irq(void);                          /* ffff3370 */
void      gic_clear_usb_pending(void);                       /* ffff3384 */
void      usb_ep_stall(void);                                /* ffff301c */
void      usb_send_zlp(void);                                /* ffff3048 */
void      usb_set_address(void);                             /* ffff2eb4 */
void      usb_get_descriptor(void);                          /* ffff2ef8 */

#endif /* BOOTROM_H */
