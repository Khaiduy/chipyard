basedir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
srcdir := $(basedir)/src

PROGRAMS ?= sha3-sw sha3-rocc wolfssl_test wolfssl_aes chachapoly_test ascon_test chachapoly_global_heap string_test chachapoly_wolfssl_official ascon_official_replica ascon_diagnostic hpke_official_replica hpke_config_check curve25519_init_test \
            drbg_memory_test test_aes test_aes_hkdf_rng test_curve25519_component_timing test_hpke_open_timing test_curve25519_timing gcd hello
CC := $(TARGET)-gcc
OBJDUMP := $(TARGET)-objdump

CFLAGS += -I $(srcdir)

hdrs := $(wildcard *.h) $(wildcard $(srcdir)/*.h)
objs ?=
ldscript ?=

%.o: $(srcdir)/%.c $(hdrs)
	$(CC) $(CFLAGS) -o $@ -c $<
%.o: %.c $(hdrs)
	$(CC) $(CFLAGS) -o $@ -c $<
%.o: %.S $(hdrs)
	$(CC) $(CFLAGS) -D__ASSEMBLY__=1 -o $@ -c $<

%.riscv: %.o $(objs) $(ldscript)
	$(CC) $(LDFLAGS) $(if $(ldscript),-T $(ldscript)) -o $@ $< $(objs)

%.dump: %.riscv
	$(OBJDUMP) -d $< > $@

.DEFAULT: elf

.PHONY: elf dumps
elf: $(addsuffix .riscv,$(PROGRAMS))
dumps: $(addsuffix .dump,$(PROGRAMS))

.PHONY: clean
clean:
	rm -f -- *.riscv *.o *.dump

.SUFFIXES:
.SUFFIXES: .o .c .S
