/* SPDX-License-Identifier: GPL-2.0 */
/*
 * usb.c - USB maskrom download mode (DWC2 OTG @ 0xff580000, GIC @ 0xff811000).
 *
 * Entered when no bootable image is found. Implements enough of a USB device to
 * expose the Rockchip "rockusb" download protocol: vendor request 0xc carries a
 * tag (0x471 = DRAM-init blob, 0x472 = loader) plus a destination; bulk OUT
 * data is CRC-checked and RC4-decoded, then dispatched to usb_download_handler
 * which validates (secure path) and launches the blob.
 *
 * USB register addresses are the exact literals from the ROM pool. Many encode
 * DWC2 device registers (DIEPCTL/DOEPCTL/GINTSTS/...); bit meanings follow the
 * Synopsys DWC2 core. Behaviour-preserving reconstruction from decompiler output.
 */
#include "bootrom.h"

/* -------- Descriptor + control-transfer leaf handlers -------------------- */

/*
 * ffff32f4 - usb_ep_tx : push 'len' bytes from 'buf' into the EP IN FIFO.
 */
void usb_ep_tx(uint32_t len, const uint32_t *buf)
{
    if ((((len & 0xffff) + 3) >> 2) <= (read32(0xff58002c) & 0xffff) &&
        (read32(0xff58002c) & 0xff0000) != 0) {
        len &= 0xffff;
        write32(0xff580910, len | 0x80000);     /* DIEPTSIZ (DAT_ffff4b98) */
        write32(0xff580900, 0x84000000);         /* DIEPCTL  (DAT_ffff4b9c) */
        for (uint32_t i = 0; i < len; i += 4)
            write32(0xff581000, *buf++);         /* EP FIFO  (DAT_ffff4ba0) */
    }
}

/*
 * ffff32b0 - usb_ep_rx : drain 'len' bytes from the EP OUT FIFO into 'buf'.
 */
void usb_ep_rx(uint32_t len, void *buf)
{
    uint32_t *p = (uint32_t *)buf;
    if ((len & 0xffff) != 0) {
        for (uint32_t i = 0; i < (len & 0xffff); i += 4)
            *p++ = read32(0xff581000);           /* DAT_ffff4b88 */
    }
    write32(0xff580b10, 0x20080040);             /* DOEPTSIZ rearm (4b90<-4b8c) */
}

/*
 * ffff3048 - usb_send_zlp : status-stage ACK (zero-length IN).
 */
void usb_send_zlp(void)
{
    usb_ep_tx(0, 0);
}

/*
 * ffff301c - usb_ep_stall : set STALL on the control endpoints.
 */
void usb_ep_stall(void)
{
    setbits32(0xff580b00, 0x200000);             /* DOEPCTL (DAT_ffff4b20) */
    setbits32(0xff580900, 0x200000);             /* DIEPCTL (DAT_ffff4b24) */
}

/*
 * ffff2eb4 - usb_set_address : program the device address (SET_ADDRESS, req 5).
 */
void usb_set_address(void)
{
    uint32_t v = read32(0xff580800) & 0xfffff80f; /* DCFG (DAT_ffff4b14) */
    write32(0xff580800, v | ((uint32_t)g_usb_dev_addr << 4));
    usb_ep_tx(0, 0);
}

/*
 * ffff2ef8 - usb_get_descriptor : return device/config descriptor from the ROM
 * templates (device @ 0xffff46a8, config @ 0xffff46bc), patched for the active
 * EP0 max-packet size, then send over EP0 IN.
 */
void usb_get_descriptor(void)
{
    extern const uint8_t usb_device_descriptor[];  /* ROM @ 0xffff46a8 */
    extern const uint8_t usb_config_descriptor[];  /* ROM @ 0xffff46bc */
    uint16_t n;
    uintptr_t buf = g_usb_databuf;

    if (g_usb_desc_type == 2) {                    /* CONFIGURATION (@0xffff46bc) */
        n = (g_usb_wlength > 9) ? 0x20 : g_usb_wlength;
        crypto_copy_bigint(buf, usb_config_descriptor, n);
        if (g_usb_ep0_maxpkt == 0x40) {            /* clamp bulk EPs to 64B (FS) */
            ((uint8_t *)buf)[0x17] = 0; ((uint8_t *)buf)[0x16] = 0x40;
            ((uint8_t *)buf)[0x1e] = 0; ((uint8_t *)buf)[0x1d] = 0x40;
        }
    } else if (g_usb_desc_type == 1) {             /* DEVICE (@0xffff46a8) */
        n = (g_usb_wlength < 0x13) ? g_usb_wlength : 0x12;
        crypto_copy_bigint(buf, usb_device_descriptor, n);
        if (g_usb_ep0_maxpkt == 0x40) {            /* bcdUSB low / maxpkt0 patch */
            ((uint8_t *)buf)[3] = 1;
            ((uint8_t *)buf)[2] = 0x10;
        }
    } else {
        setbits32(0xff580b00, 0x200000);           /* stall (DAT_ffff4b18/1c) */
        setbits32(0xff580900, 0x200000);
        return;
    }
    usb_ep_tx(n, (const uint32_t *)buf);
}

/* -------- PHY / core / reset -------------------------------------------- */

/*
 * ffff3054 - usb_phy_reset : pulse the USB PHY soft-reset via CRU 0xff44031c.
 */
void usb_phy_reset(void)
{
    write32(0xff44031c, 0x4000400);               /* DAT_ffff4b28 */
    rom_delay(1);
    write32(0xff44031c, 0x2000200);
    rom_delay_ms(10);
    write32(0xff44031c, 0x2000000);
    rom_delay_ms(3);
    write32(0xff44031c, 0x4000000);
}

/*
 * ffff3658 - usb_set_speed : read the enumerated speed and set EP0 / bulk
 * max-packet sizes accordingly.
 */
void usb_set_speed(void)
{
    g_usb_bulk_maxpkt = 0x40;
    g_usb_ep0_maxpkt  = 0x40;
    uint32_t spd = (read32(0xff580808) >> 1) & 3;  /* DSTS (DAT_ffff4c04) */
    if (spd != 3 && spd != 1) {
        if (spd != 0) {
            setbits32(0xff580900, 3);              /* DAT_ffff4c08 */
            g_usb_bulk_maxpkt = 8;
            goto cfg;
        }
        g_usb_ep0_maxpkt = 0x200;
    }
    clrbits32(0xff580900, 3);
cfg:
    write32(0xff580b00, 0x20080040 /* DAT_ffff4c0c -> 4c10 */);
    setbits32(0xff580b00, 0x80000000);             /* DAT_ffff4c14 */
    setbits32(0xff580818, 0x100);                  /* DAT_ffff4c18 */
}

/*
 * ffff30b4 - usb_core_init : DWC2 core power-up, soft-reset, EP0/EP1 FIFO and
 * interrupt-mask programming. Reproduced verbatim (opaque DWC2 field writes).
 */
void usb_core_init(void)
{
    /* wait for AHB idle, then soft-reset the core */
    { uint64_t i = 1; while ((int)read32(0xff580010) >= 0) { if ((uint32_t)(i >> 4) >= 0x271) break; i++; } }
    setbits32(0xff580010, 1);                       /* GRSTCTL (DAT_ffff4b2c) */
    { uint64_t i = 1; while (read32(0xff580010) & 1) { if ((uint32_t)(i >> 4) >= 0x271) break; i++; } }

    write32(0xff580e00, 0);                          /* DAT_ffff4b30 */
    clrbits32(0xff580800, 3);                        /* DAT_ffff4b34 */
    clrbits32(0xff580800, 0x7f0);
    write32(0xff580028, (read32(0xff580028) & 0xffff0000) | 0x200); /* GRXFSIZ 4b38 */
    setbits32(0xff580010, 0x420);
    { uint64_t i = 1; while (read32(0xff580010) >> 5 & 1) { if ((uint32_t)(i >> 4) >= 0x271) break; i++; } }
    setbits32(0xff580010, 0x10);
    { uint64_t i = 1; while (read32(0xff580010) >> 4 & 1) { if ((uint32_t)(i >> 4) >= 0x271) break; i++; } }
    setbits32(0xff580010, 8);

    write32(0xff580910, 0x48000000);                 /* DIEPTSIZ/CTL (4b3c..)  */
    write32(0xff580914, 0);
    write32(0xff580908, 0);
    write32(0xff580810, 0xff);
    write32(0xff580b00, 0x48000000);
    write32(0xff580b10, 0);
    write32(0xff580b14, 0);
    write32(0xff580b08, 0xff);
    write32(0xff580810, 0x2f);                        /* DAT_ffff4b5c */
    write32(0xff580814, (read32(0xff580040) <= 0x4f543009u) ? 0xf : 0x2f); /* 4b60/64/68 */
    write32(0xff580818, 0xffffffff);
    write32(0xff58081c, 0x10001);
    write32(0xff580014, 0xffffffff);                 /* DAT_ffff4b74 */
    write32(0xff580004, 0xffffffff);                 /* DAT_ffff4b78 */
    write32(0xff580018, 0xc00c3c10);                 /* DAT_ffff4b7c -> 4b80   */
    setbits32(0xff580008, 1);                        /* GINTMSK (DAT_ffff4b84) */
}

/*
 * ffff3398 - usb_bus_reset : connect / reset handler - resets FIFOs, unmasks
 * interrupts and enables async aborts/IRQs.
 */
void usb_bus_reset(void)
{
    setbits32(0xff580808, 1);                        /* DAT_ffff4bac */
    clrbits32(0xff580808, 8);
    write32(0xff580e00, 0xff);                       /* DAT_ffff4bb0 */
    clrbits32(0xff580818, 0x8000);                   /* DAT_ffff4bb4 */
    write32(0xff580b08, 0xffffffff);                 /* DAT_ffff4bb8 */
    write32(0xff580908, 0xffffffff);                 /* DAT_ffff4bbc */
    write32(0xff58090c, 0xffffffff);                 /* DAT_ffff4bc0 */
    write32(0xff580b0c, 0xffffffff);                 /* DAT_ffff4bc4 */
    write32(0xff580818, 0x1000000);                  /* DAT_ffff4bc8 */
    write32(0xff580834, 1);                          /* DAT_ffff4bcc */
    cpu_enable_irq_abort();
}

/*
 * ffff3dfc - usb_otg_init : full device-mode bring-up.
 */
void usb_otg_init(void)
{
    g_usb_download_done = 0;
    g_usb_databuf = 0xff0900a8;
    MMIO32(0xff0900a4) = 0;
    usb_bus_reset();
    setbits32(0xff580804, 2);                        /* GAHBCFG (DAT_ffff4c48) */
    usb_phy_reset();
    usb_core_init();
    clrbits32(0xff580804, 2);
    gic_enable_usb_irq();
}

/*
 * ffff3ed8 - usb_maskrom_mode : raise clocks, init USB, and wait for a complete
 * download (g_usb_download_done). The actual transfer is driven by usb_isr().
 */
void usb_maskrom_mode(void)
{
    g_sig_ok = 0;
    cru_pll_init();
    usb_otg_init();
    while (g_usb_download_done == 0)
        ;
}

/* -------- GIC leaf helpers (ffff3370 / ffff3384) ------------------------- */
void gic_enable_usb_irq(void)    { write32(0xff811104, 0x800000); } /* GICD_ISENABLER1 */
void gic_clear_usb_pending(void) { write32(0xff811184, 0x800000); } /* GICD_ICPENDR1   */

/*
 * ffff3434 - gic_irq_handler : GIC top half, called from the EL3 IRQ vector
 * (ffff0a80, "current EL, SPx"), which saves x0..x18/x30, calls this and ERETs.
 * Ghidra did not find it because its only caller is the exception vector table.
 *
 * It acknowledges one interrupt and services it only if it is the OTG SPI 55
 * (0x37 = CPU 0, INTID 55).  Anything else is acknowledged and dropped without
 * an EOI.
 *
 * NOTE: on a download, usb_isr() reaches usb_download_handler(), which jumps to
 * the downloaded image (0x471/0x472 "GO") and never returns.  The GICC_EOIR
 * write below is then never executed: the loader runs inside this exception
 * with SPI 55 still ACTIVE and CPU0's GIC running priority at its highest
 * level.  TPL returns here, so its IRQ is completed; SPL does not.  This is the
 * cause of the RK3328 all-USB boot hang at "smp: Bringing up secondary CPUs";
 * the fix is for SPL to write GICC_EOIR = 55 itself.
 * See https://github.com/stroma123/rk3328-bootrom
 */
void gic_irq_handler(void)
{
    uint32_t iar = read32(0xff81200c);               /* GICC_IAR  (lit 4bd0) */
    if (iar != 0x37)
        return;                                      /* not OTG: no EOI      */
    usb_isr();
    write32(0xff812010, 0x37);                       /* GICC_EOIR (lit 4bd4) */
}

/* -------- Interrupt + transfer state machine ---------------------------- */

/*
 * ffff3708 - usb_handle_gintsts : service core (GINTSTS) interrupt bits.
 */
void usb_handle_gintsts(void)
{
    if ((read32(0xff580818) & read32(0xff58081c) & 0xffff) != 0) {  /* DAT_ffff4c1c/20 */
        uint32_t s = ((read32(0xff580834) & 1) << 7 | read32(0xff580810)) & read32(0xff580908);
        uint32_t lo = s & 0x2f;
        if (lo) write32(0xff580908, lo);
        if ((s >> 7) & 1) write32(0xff580908, 0x10);
    }
}

/*
 * ffff3780 - usb_handle_ep_ints : per-endpoint OUT/IN interrupt processing.
 */
void usb_handle_ep_ints(void)
{
    uint32_t pend = (read32(0xff58081c) & read32(0xff580818)) >> 16; /* DAELINT */
    if (pend == 0)
        return;
    uint32_t maxpkt = g_usb_bulk_maxpkt;
    for (uint32_t ep = 0, off = 8; off != 0x68; ep++, off += 0x20) {
        if ((1u << (ep & 0x1f)) & pend) {
            uint32_t sts = read32(0xff580814) & read32(0xff580b00 + off); /* 4c3c/38 */
            if ((sts & 1) && (write32(0xff580b00 + off, 1), ep != 0)) {
                write32(0xff580910, maxpkt | 0x80000);   /* re-arm IN (4c40) */
                setbits32(0xff580900, 0x84000000);       /* DAT_ffff4c44 */
            }
            if ((sts >> 5) & 1) write32(0xff580b00 + off, 0x20);
            if ((sts >> 1) & 1) write32(0xff580b00 + off, 2);
            if ((sts >> 2) & 1) write32(0xff580b00 + off, 4);
            if ((sts >> 3) & 1) write32(0xff580b00 + off, 8);
        }
    }
}

/*
 * ffff2e68 helper region: usb_ep_dispatch (ffff355c) switches on the EP0
 * transfer phase and invokes the matching handler. The ROM uses a jump table
 * (switchdataD_ffff4680) with 5 targets; reconstructed as a switch.
 */
void usb_ep_dispatch(void)
{
    uint32_t reg = read32(0xff580b40);               /* DOEPINT0 (DAT_ffff4bec) */
    if ((reg & 0xf) == 0) {
        uint32_t phase = ((reg >> 0x11) & 0xf) - 2;
        if (phase < 5) {
            switch (phase) {                         /* targets @ ffff4680 */
            case 0: usb_handle_setup();      break;  /* ffff35c8 (approx)   */
            case 1: usb_handle_setup();      break;  /* ffff35b0            */
            case 2: usb_handle_setup();      break;  /* ffff35b0            */
            case 3: usb_set_speed();         break;  /* ffff3620            */
            case 4: usb_handle_setup();      break;  /* ffff35d8            */
            }
        }
    }
}

/*
 * ffff3474 - usb_isr : top-level interrupt handler. Reads GINTSTS, dispatches
 * reset / enumeration-done / setup / EP / download events, and acks.
 */
void usb_isr(void)
{
    uint32_t gintsts = read32(0xff580804) & read32(0xff580808); /* 4bd8/4bdc */
    if (gintsts == 0)
        return;

    if ((gintsts >> 4) & 1) {                        /* RXFLVL -> EP dispatch */
        clrbits32(0xff580808, 0x10);
        usb_ep_dispatch();
        setbits32(0xff580808, 0x10);
    }
    if ((gintsts >> 5) & 1) {                        /* NPTXFE */
        write32(0xff580834, 0);                      /* DAT_ffff4be0 */
        clrbits32(0xff580808, 0x20);
    }
    if ((gintsts >> 0xc) & 1) {                      /* USBRST */
        g_usb_state = 0;
        g_usb_download_done = 0;
        clrbits32(0xff580b50, 1);                    /* DAT_ffff4be4 */
        write32(0xff580804, 0x1000);
    }
    if ((gintsts >> 0xd) & 1) {                      /* ENUMDONE */
        usb_set_speed();
        write32(0xff580804, 0x2000);
    }
    if ((gintsts >> 0x12) & 1) usb_handle_gintsts(); /* IN EP int  */
    if ((gintsts >> 0x13) & 1) usb_handle_ep_ints(); /* OUT EP int */

    uint32_t rest = gintsts & read32(0xff580840 /* DAT_ffff4be8 */);
    if (rest) write32(0xff580804, rest);             /* ack remaining */
}

/*
 * ffff3aa8 - usb_handle_setup : fetch the 8-byte SETUP packet and parse it.
 */
void usb_handle_setup(void)
{
    usb_ep_rx(8, (void *)(uintptr_t)0xff090084);     /* &g_usb_setup */
    usb_parse_control_request();
}

/*
 * ffff3ad0 - usb_parse_control_request
 * Vendor OUT (type 0x40) request 0xc is the rockusb download command: it latches
 * the destination and, for tag 0x471/0x472, seeds the expected load header.
 * Standard requests handle SET_ADDRESS(5)/GET_DESCRIPTOR(6)/SET_CONFIG(9).
 */
void usb_parse_control_request(void)
{
    uint8_t breq = g_usb_setup_brequest & 0xf;

    if ((g_usb_setup_bmreq & 0x60) == 0x40) {        /* vendor request */
        if (breq == 0xc) {
            if (g_usb_download_done == 0) {
                MMIO16(0xff09008c) = 0;              /* reset rx offset */
            }
            if (MMIO32(0xff09008c) != 0) {
                MMIO16(0xff090098) = g_usb_wlength;
                g_usb_state = 1; g_usb_download_done = 1;
                return;
            }
            if (g_usb_download_tag == RKUSB_TAG_LOADER) {       /* 0x472 */
                for (int i = 0; i < 8; i++) ((uint8_t *)0xff090090)[i] = 0;
                MMIO16(0xff090098) = g_usb_wlength;
                g_usb_state = 1; g_usb_download_done = 1;
                return;
            }
            if (g_usb_download_tag != RKUSB_TAG_DRAM) {         /* other */
                MMIO16(0xff090098) = g_usb_wlength;
                g_usb_state = 1; g_usb_download_done = 1;
                return;
            }
            /* 0x471 : DRAM-init blob loads to fixed SRAM address 0xff091000 */
            uint8_t *dst = (uint8_t *)0xff090090;
            dst[0]=0x00; dst[1]=0x10; dst[2]=0x09; dst[3]=0xff;
            dst[4]=0; dst[5]=0; dst[6]=0; dst[7]=0;
            MMIO16(0xff090098) = g_usb_wlength;
            g_usb_state = 1; g_usb_download_done = 1;
            return;
        }
    } else if ((g_usb_setup_bmreq & 0x60) == 0) {    /* standard request */
        if (breq == 9) { usb_send_zlp();       return; }  /* SET_CONFIGURATION */
        if (breq == 6) { usb_get_descriptor(); return; }  /* GET_DESCRIPTOR    */
        if (breq == 5) { usb_set_address();    return; }  /* SET_ADDRESS       */
    }
    usb_ep_stall();
}

/*
 * ffff3858 - usb_rx_data_pump : accumulates bulk-OUT download data into the
 * destination buffer, and when a complete blob has arrived, CRC/RC4-decodes it
 * (usb_blob_decode) and hands it to usb_download_handler.
 */
void usb_rx_data_pump(uint64_t count)
{
    if (g_usb_download_done == 0)
        return;

    if (g_usb_state == 1) {
        usb_ep_rx((uint32_t)count, (void *)(uintptr_t)g_usb_databuf);
        crypto_copy_bigint(MMIO32(0xff090090), (const void *)(uintptr_t)g_usb_databuf,
                           (int)(count & 0xffff));
        MMIO16(0xff09008c) += (uint32_t)count & 0xffff;
        uint32_t remain = (uint32_t)MMIO16(0xff090098) - ((uint32_t)count & 0xffff);
        MMIO16(0xff090098) = (uint16_t)remain;
        MMIO32(0xff090090) += (uint32_t)count & 0xffff;

        if ((remain & 0xffff) == 0) {                /* blob complete */
            uint32_t total = MMIO16(0xff09008c);
            if ((total & 0xfff) != 0) {
                if (usb_blob_decode(MMIO32(0xff090090) - total, total) == 0) {
                    g_boot_stage = 10;
                    usb_download_handler(0xff090084);
                }
                MMIO16(0xff09008c) = 0;
            }
            g_usb_state = 2;
            usb_ep_tx(0, 0);
        }
    } else if (g_usb_state == 2) {
        g_usb_state = 0;
    }
}

/*
 * ffff3e6c - usb_blob_decode : verify the trailing CRC-16 of a downloaded blob
 * and, if valid, RC4-decode it in place. Returns 0 on success.
 */
int usb_blob_decode(uintptr_t buf, int len)
{
    uint8_t *p = (uint8_t *)buf;
    uint16_t stored = (uint16_t)((p[len - 2] << 8) | p[len - 1]);
    uint16_t calc = crc16_ccitt(p, len - 2);
    int bad = (stored != calc);
    if (!bad)
        rc4_crypt(p, len - 2);
    return bad;
}

/*
 * ffff3c2c - usb_download_handler
 * Processes a decoded blob by its tag: 0x471 runs a DRAM-init payload in place;
 * 0x472 validates (secure path: SHA+RSA) and launches the loader. The embedded
 * "RSAK"/"RK32" markers gate the secure chain, matching boot_load_image().
 */
void usb_download_handler(uintptr_t pkt)
{
    uint8_t *pk = (uint8_t *)pkt;
    uint16_t tag = *(uint16_t *)(pk + 4);
    uint32_t sz  = *(uint32_t *)(pk + 8);
    uintptr_t end = *(uintptr_t *)(pk + 0xc);
    int body = (int)(sz - 2);
    uint8_t *code = (uint8_t *)(end - sz);

    if (tag == RKUSB_TAG_DRAM) {                     /* 0x471 */
        uint32_t first = *(uint32_t *)code;
        if (g_secure_boot == 0) {
            if (first == MAGIC_RSAK) return;         /* signed blob, skip in NS */
        } else {
            if (first == MAGIC_RSAK) {
                if (secure_boot_header_verify(code) != 0) return;
                g_sig_ok = 1;
                crypto_copy_bigint(0xff09003c, (void *)(end + (800 - sz)), 0x44);
                return;
            }
            if (g_sig_ok == 0) return;
            sha_start(body);
            sha_update_dma(code, body);
            if (sha_final_compare((void *)0xff09003c) != 0) { g_sig_ok = 0; return; }
            first = *(uint32_t *)code;
        }
        if (first == MAGIC_RK32)
            code = (uint8_t *)(end + (4 - sz));
    } else if (tag == RKUSB_TAG_LOADER) {            /* 0x472 */
        usb_ep_tx(0, 0);
        gic_clear_usb_pending();
        if (g_secure_boot != 0) {
            if (g_sig_ok == 0) return;
            sha_start(body);
            sha_update_dma(code, body);
            if (sha_final_compare((void *)0xff090060) != 0) { g_sig_ok = 0; return; }
        }
    } else {
        return;
    }
    ((void (*)(void))code)();                         /* launch */
}
