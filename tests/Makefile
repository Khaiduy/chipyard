#################################
# RISCV Toolchain
#################################

PREFIX = riscv64-unknown-elf-

GCC = $(PREFIX)gcc
CXX = $(PREFIX)g++
CP = $(PREFIX)objcopy
OBJDUMP = $(PREFIX)objdump
DG = $(PREFIX)gdb
SIZE = $(PREFIX)size


#################################
# Flags
#################################

# SoC Settings
#ARCH = rv64imafdc
ARCH = rv32imafc_zicsr
#ABI = lp64d
ABI = ilp32f
ARCHFLAGS = -march=$(ARCH) -mabi=$(ABI)

CFLAGS  = -std=gnu99 -O2 -fno-common -fno-builtin-printf -Wall
CFLAGS += $(ARCHFLAGS)
LDFLAGS = -static -march=$(ARCH) -mabi=$(ABI)

include libgloss.mk

PROGRAMS = pwm blkdev accum charcount nic-loopback big-blkdev pingd \
           streaming-passthrough streaming-fir nvdla spiflashread spiflashwrite fft gcd \
           hello mt-hello genkat ascon


.DEFAULT_GOAL := default


#################################
# Build
#################################

spiflash.img: spiflash.py
	python3 $<

%.o: %.S
	$(GCC) $(CFLAGS) -D__ASSEMBLY__=1 -c $< -o $@

%.o: %.c mmio.h spiflash.h
	$(GCC) $(CFLAGS) -c $< -o $@

%.riscv: %.o $(libgloss)
	$(GCC) $(LDFLAGS) $< -o $@

%.dump: %.riscv
	$(OBJDUMP) -D $< > $@


#################################
# Recipes
#################################

.PHONY: clean
clean:
	rm -f *.riscv *.o *.dump
	$(if $(libgloss),rm -rf $(libgloss_builddir)/)

.PHONY: default
default: $(addsuffix .riscv, $(PROGRAMS)) spiflash.img

.PHONY: dumps
dumps: $(addsuffix .dump, $(PROGRAMS))

#################################
# Additional target for genkat
#################################

genkat: ascon-c/crypto_aead/ascon128v12/opt32/*.c ascon-c/crypto_aead/ascon128v12/opt32/*.h ascon-c/tests/genkat_aead.c
	$(GCC) $(CFLAGS) -L libgloss -Iascon-c/crypto_aead/ascon128v12/opt32 $^ -o $@

ascon.riscv: $(wildcard test_ascon/*.c) $(wildcard test_ascon/*.h)
	$(GCC) $(CFLAGS) -L libgloss -I test_ascon $^ -o $@ -Wl,-melf32lriscv

