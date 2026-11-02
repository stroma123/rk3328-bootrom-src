# RK3328 BootROM — Reconstruction Notes

Source: `bootrom.elf` — AArch64 (ARMv8-A), little-endian, image base `0xffff0000`,
32 KB `.text`, 87 functions, no symbols. Built with `GCC (GNU) 4.7.2`.
SHA-256 `b443546c88ac78a1a6b10c0928c3a7016e7f8995483917e6a2031923c41a27d8`.

Reconstructed by static analysis in Ghidra via the GhidraMCP bridge. **The ELF
was never modified**; only the Ghidra database was annotated (function renames).
The decompiler output is the source of truth — this reconstruction preserves
*behaviour*, not the original source text.

## How to read this tree

```
include/rk3328_regs.h   MMIO bases/offsets (confirmed from the constant pool)
include/bootrom.h       shared SRAM state block, magics, all prototypes
src/start.c             reset vector (pre-C, documented from raw bytes)
src/util.c              delays, mem*, CRC-16, CPU state
src/otp.c               secure OTP (OTP_S, 0xff0a0000) + two read protocols
src/efuse.c             secure eFuse (EFUSE_S, 0xff0b0000)
src/crypto.c            SHA-256 + RSA-2048 + RC4 (0xff060000)
src/secure_boot.c       security-config probe + signed-header verify
src/clock.c             CRU PLL/clock bring-up (0xff440000)
src/storage_spi.c       SPI-NOR/NAND boot driver (0xff190000)
src/storage_mmc.c       DW-MMC (eMMC/SD) boot driver (0xff500000/0xff520000)
src/boot.c              boot-device table, image load/verify/launch, main()
src/usb.c               USB maskrom download mode (DWC2 @ 0xff580000)
src/bootrom_rodata.c    exact ROM constants (RC4 table, USB descriptors)
docs/function_map.csv   all 87 functions: address -> name, module, confidence
```

Every function carries its original ROM address in a comment and in
`function_map.csv`, so the mapping back to the binary is never lost.

## Top-level flow

```
reset_entry (0xffff0000, asm)         primary-CPU gate, clear regs, set SP
  └─ bootrom_main (0xffff4288)
       set_timer_clock(24)            udelay reference = 24 MHz
       cru_early_init()               initial CRU setup
       g_secure_boot = 0
       read_security_config()         probe OTP/eFuse -> secure-boot state
       cru_pll_init()                 raise clock to 200/400 MHz
       boot_try_devices()             try eMMC, SPI-NOR, SPI-NAND, SD
         └─ boot_load_image()         load IDB, RC4-decode, verify, launch
       usb_maskrom_mode()             fall back to USB download (rockusb)
       for(;;)
```

## Memory / peripheral map (confirmed from access patterns)

| Base        | Block                         | Evidence |
|-------------|-------------------------------|----------|
| 0xff060000  | Crypto (SHA-256, RSA-2048)    | "RK32" magic; digest/RSA banks |
| 0xff090000  | On-chip SRAM scratch/state    | all `_DAT_ff09xxxx` globals |
| 0xff091000  | IDB / download staging buffer | boot_load_image, rockusb |
| 0xff0a0000  | secure OTP (OTP_S)            | otp_read_proto_a/_b |
| 0xff0b0000  | secure eFuse (EFUSE_S)        | efuse_read/program |
| 0xff0d0000  | Secure GRF (write masks)      | OTP/eFuse unlock |
| 0xff100000  | GRF (iomux etc.)              | SPI/MMC pad setup |
| 0xff190000  | SPI master                    | spi_xfer |
| 0xff440000  | CRU (PLL/clock/reset)         | clock.c, resets |
| 0xff500000  | DW-MMC host 0 (SD)            | mmc driver |
| 0xff520000  | DW-MMC host 1 (eMMC)         | mmc driver |
| 0xff580000  | DWC2 USB-OTG                  | usb.c |
| 0xff811000  | GIC-400 distributor           | gic_enable_usb_irq |

## Key magics / constants

| Value        | Meaning |
|--------------|---------|
| 0x4b415352 "RSAK" | signed-image header tag |
| 0x32334b52 "RK32" | code-section end tag |
| 0xfcdc8c3b        | IDB sector-0 magic |
| 0x0471 / 0x0472   | rockusb download tags (DRAM-init / loader) |
| VID 0x2207 / PID 0x320c | Rockchip / RK3328 USB IDs |
| RC4 seed @ 0xffff46e0 | fixed Rockchip RC4 key table (see bootrom_rodata.c) |

## Security model (as implemented)

* `read_security_config()` reads eFuse word 0 with 4-bit majority voting to decide
  whether the OTP block exists and which read protocol it uses, then reads OTP
  word 0x80 — `0xff` enables secure boot (`g_secure_boot`) and sets the key word
  count.
* Secure images carry an `"RSAK"` header. `secure_boot_header_verify()` checks a
  key hash against fuses/OTP, then the image is hashed (SHA-256) and the RSA-2048
  signature is recovered and compared to the hash.
* Stored boot images and USB blobs are RC4-obfuscated with the fixed table above;
  USB blobs additionally carry a CRC-16/CCITT trailer.

## Confidence & uncertainties

* **High confidence** (behaviour matches decompiler 1:1): util, otp, crypto
  primitives, clock, SPI/MMC command flows, USB control/descriptor handling,
  boot table and main.
* **Medium / marked UNCERTAIN in code:**
  * `otp_read_proto_a/_b` — Ghidra lost the base-pointer register setup
    (`unaff_wNN`); bases `0xff0a0000` / `0xff270000` were recovered from the
    immediate arithmetic. Register *sequence* is reproduced verbatim; field
    semantics are inferred.
  * `secure_boot_header_verify` — the OTP-key-compare branch is a close but not
    byte-exact transliteration (two memcmp uses were consolidated); the control
    flow and the SHA/RSA path are faithful.
  * `boot_load_image` / `usb_download_handler` — intricate header parsing;
    transliterated closely, inner offsets preserved.
  * `start.c` — reset vector is hand-written asm, not a Ghidra function; only the
    first block was disassembled, the rest is modelled behaviourally.
  * Several register *offset names* in `rk3328_regs.h` are inferred from usage and
    marked UNCERTAIN; the raw addresses are exact.

Nothing in this tree asserts behaviour that is not present in the binary.
Inferred items are commented `UNCERTAIN` and listed above.

## Function coverage — 87 / 87

All 86 functions Ghidra detected were analysed and renamed. An 87th,
`gic_irq_handler` (0xffff3434), was added by hand: Ghidra missed it because its
only caller is the EL3 IRQ vector at 0xffff0a80. 84 carry meaningful names;
2 are compiler-generated thunks (`thunk_FUN_ffff442c` at 0xffff440c and
`thunk_FUN_ffff4560` at 0xffff4554) that simply forward to `memcpy_aligned` /
`memset_words`. **No functions remain unprocessed.**

## Build

```
make            # host freestanding build: compiles every module to a .o
```
This is a study reconstruction, not a flashable ROM. A real image build would add
an AArch64 toolchain, `start.S` (from the vector bytes documented in `start.c`),
and a linker script placing `.text` at `0xffff0000`.
