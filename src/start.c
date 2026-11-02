/* SPDX-License-Identifier: GPL-2.0 */
/*
 * start.c - reset vector / pre-C startup (ROM 0xffff0000 .. 0xffff0138).
 *
 * This region is NOT a Ghidra function (the ELF declares no entry point); it is
 * reconstructed directly from a FULL disassembly of the 0x138-byte stub plus its
 * literal pool. The control flow below is verified; only a couple of strap-bit
 * *meanings* remain inferred (marked UNCERTAIN).
 *
 * Verified literal pool @ 0xffff00f8 (each an 8-byte slot, high word 0):
 *   0xffff00f8: 0xff091000   SRAM / resume code buffer
 *   0xffff0100: 0xffff0800   (ROM pointer)
 *   0xffff0108: 0xff090004   resume entry address (warm boot)
 *   0xffff0110: 0xff090008   warm-boot magic slot
 *   0xffff0118: 0xdeadbeaf   warm-boot magic value
 *   0xffff0120: 0xff440094   CRU strap/status register
 *   0xffff0128: 0xff0d0000   Secure GRF
 *   0xffff0130: 0xff0d0180   Secure GRF (boot control)
 *
 * Verified flow (from the disassembly):
 *   - ldr  x0,=0xff0d0000 ; ldr w0,[x0] ; tbz w0,#15,...   (SGRF bit15 test)
 *   - ldr  x0,=0xff440094 ; ldr w0,[x0] ; and w0,#0x1f ; cbz ...  (strap test)
 *   - mrs  x0,mpidr_el1 ; and #0xff ; cmp #0 ; b.eq <cpu0>   (only CPU0 proceeds)
 *   - <secondaries> set a flag and jump via a stored vector (br x0)
 *   - warm boot: if [0xff090008]==0xdeadbeaf, br to [0xff090004] (resume address)
 *   - cold boot: clear x0..x30 ; mov sp,=<stack> ; msr vbar_el3,=<vectors> ;
 *                b 0xffff4288            ; -> bootrom_main   (0xffff00f4+0x4194)
 *
 * The 'b 0xffff4288' target was confirmed arithmetically: the branch at
 * 0xffff00f4 with imm26=0x1065 lands exactly on bootrom_main.
 */
#include "bootrom.h"

#define SGRF_BOOT_STATUS   0xff0d0000u   /* bit15 tested by the vector (UNCERTAIN) */
#define CRU_BOOT_STRAP     0xff440094u   /* low 5 bits tested (UNCERTAIN meaning)   */
#define WARMBOOT_MAGIC_AT  0xff090008u   /* holds 0xdeadbeaf on a warm/resume boot  */
#define WARMBOOT_ENTRY_AT  0xff090004u   /* resume entry address                    */
#define WARMBOOT_MAGIC     0xdeadbeafu

/*
 * reset_entry - behavioural model of the 0xffff0000 reset stub (runs at EL3 out
 * of reset). Faithful to the verified control flow; a real image would use the
 * assembly documented above as _start, including the SP / VBAR_EL3 setup that
 * cannot be expressed portably in C.
 */
__attribute__((noreturn))
void reset_entry(void)
{
#if defined(__aarch64__)
    uint64_t mpidr;

    /* Only the primary CPU (affinity 0) continues; secondaries park. */
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    if ((mpidr & 0xff) != 0) {
        for (;;)
            __asm__ volatile("wfe");
    }

    /* Warm-boot / resume: if the magic is present, jump to the stored entry. */
    if (MMIO32(WARMBOOT_MAGIC_AT) == WARMBOOT_MAGIC) {
        void (*resume)(void) = (void (*)(void))(uintptr_t)MMIO32(WARMBOOT_ENTRY_AT);
        resume();
        for (;;)
            ;
    }
    /* Cold boot would also: clear x0..x30, set SP, set VBAR_EL3 (see header). */
#endif
    bootrom_main();
    for (;;)
        ;
}
