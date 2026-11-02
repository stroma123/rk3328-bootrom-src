# Makefile - reconstructed RK3328 BootROM
#
# This is a *reconstruction* for study, not a drop-in ROM build. It compiles
# each module to an object file to demonstrate the sources are well-formed C.
# A real ROM image would add: an AArch64 toolchain, start.S (from the vector
# bytes in start.c), a linker script placing .text at 0xffff0000, and EL3 setup.
#
# Host syntax/`-c` build (default):   make
# Cross build (if available):          make CROSS=aarch64-linux-gnu-

CROSS   ?=
CC       = $(CROSS)gcc
CFLAGS   = -std=c11 -ffreestanding -fno-builtin -Iinclude -Wall \
           -Wno-unused -Wno-misleading-indentation -Os
ifneq ($(CROSS),)
CFLAGS  += -mgeneral-regs-only
endif

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)

all: $(OBJS)
	@echo "Built: $(OBJS)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o

.PHONY: all clean
