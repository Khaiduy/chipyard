bmarkdir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# SoC Settings
#ARCH = rv64imafdc
ARCH = rv32imafc
#ABI = lp64d
ABI = ilp32f
ARCHFLAGS = -march=$(ARCH) -mabi=$(ABI)


TARGET := riscv64-unknown-elf
CFLAGS := -mcmodel=medany -std=gnu99 -O2 -fno-common -fno-builtin-printf -Wall -fno-tree-loop-distribute-patterns
CFLAGS += $(ARCHFLAGS)
LDFLAGS := -static -nostartfiles -lgcc -march=$(ARCH) -mabi=$(ABI)

PROGRAMS := sha3-rocc sha3-sw

objs := crt.o syscalls.o
ldscript := link.ld

include $(bmarkdir)/../common.mk

