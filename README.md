# RK3328 BootROM — Reconstructed C Source

A behaviour-preserving C reconstruction of the Rockchip **RK3328** mask BootROM
(`bootrom.elf`, AArch64, 32 KB @ `0xffff0000`, 87 functions), recovered by static
analysis in Ghidra.

> This is a study/reference reconstruction, not the original source and not a
> flashable image. It preserves the *behaviour* shown by the decompiler, not the
> original implementation text. The original ELF is never modified.

## Layout

| Path | Contents |
|------|----------|
| `include/rk3328_regs.h` | MMIO bases/offsets |
| `include/bootrom.h` | SRAM state block, magics, all prototypes |
| `src/start.c` | reset vector (documented from raw bytes) |
| `src/util.c` | delays, `mem*`, CRC-16, CPU state |
| `src/otp.c` | secure OTP (OTP_S @ 0xff0a0000) + two read protocols |
| `src/efuse.c` | secure eFuse (EFUSE_S @ 0xff0b0000) |
| `src/crypto.c` | SHA-256, RSA-2048, RC4 |
| `src/secure_boot.c` | secure-boot probe + header verify |
| `src/clock.c` | CRU PLL/clock bring-up |
| `src/storage_spi.c` | SPI-NOR / SPI-NAND driver |
| `src/storage_mmc.c` | DW-MMC (eMMC/SD) driver |
| `src/boot.c` | boot table, image load/verify/launch, `main` |
| `src/usb.c` | USB maskrom download mode |
| `src/bootrom_rodata.c` | exact ROM constant tables |
| `docs/function_map.csv` | all 87 functions → names, modules, confidence |
| `docs/RECONSTRUCTION_NOTES.md` | architecture, register map, uncertainties |

## Build

```sh
make                       # host freestanding build (compiles each module to .o)
make CROSS=aarch64-linux-gnu-   # cross-compile if a toolchain is present
```

All 12 modules compile cleanly. See `docs/RECONSTRUCTION_NOTES.md` for the
top-level flow, memory map, security model, and the list of items marked
`UNCERTAIN`.

## Related

The annotated disassembly and the investigation of the RK3328 all-USB boot hang
are in [rk3328-bootrom](https://github.com/stroma123/rk3328-bootrom). The cause
is in `gic_irq_handler()` (`src/usb.c`, ROM 0xffff3434): the BootROM starts the
downloaded loader from inside this IRQ handler and never writes `GICC_EOIR`.

## License

GPL-2.0, see [LICENSE](LICENSE).
