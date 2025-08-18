#################################
# RISCV Toolchain
#################################

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR := $(ROOT_DIR)build

CC=$(RISCV)/bin/riscv64-unknown-elf-gcc
OBJCOPY=$(RISCV)/bin/riscv64-unknown-elf-objcopy
OBJDUMP=$(RISCV)/bin/riscv64-unknown-elf-objdump
CFLAGS=-march=rv64imac_zicsr_zifencei -mcmodel=medany -O0 -std=gnu11 -Wall -nostartfiles
CFLAGS+= -fno-common -g -DENTROPY=0 -mabi=lp64d -DNONSMP_HART=0
CFLAGS+= -I $(ROOT_DIR)/include -I.
LFLAGS=-static -nostdlib -L $(ROOT_DIR)/linker -T hello.elf.lds

PBUS_CLK ?= 1000000

DRIVER_O= \
	driver/trng/trng.o \
	driver/chacha/chacha.o \
	driver/poly/poly.o \
	driver/ecdsa/ecdsa.o \
	driver/aes/aes.o \
	driver/uart/uart.o 
		
LIB_FS_O= driver/memcpy.o \
		driver/memset.o

default : elf bin dump
CRT := crt0.S

elf := $(BUILD_DIR)/hello.elf
$(elf): hello.c kprintf.c $(CRT) $(LIB_FS_O) $(DRIVER_O)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -DTL_CLK="$(PBUS_CLK)UL" $(LFLAGS) -o $@ $(LIB_FS_O) $(DRIVER_O) $(CRT) hello.c kprintf.c

.PHONY: elf
elf: $(elf)

bin := $(BUILD_DIR)/hello.bin
$(bin): $(elf)
	mkdir -p $(BUILD_DIR)
	$(OBJCOPY) -O binary $< $@


.PHONY: bin
bin: $(bin)

dump := $(BUILD_DIR)/hello.dump
$(dump): $(elf)
	$(OBJDUMP) -D -S $< > $@

.PHONY: dump
dump: $(dump)

.PHONY: clean
clean::
	rm -rf $(BUILD_DIR)
