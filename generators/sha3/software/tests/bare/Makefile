bmarkdir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

TARGET := riscv64-unknown-elf

# wolfSSL paths
WOLFSSL_INCLUDE := /usr/local/include
WOLFSSL_LIB := /usr/local/lib

CFLAGS := -mcmodel=medany -std=gnu99 -O2 -fno-common -fno-builtin-printf -Wall -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -Wno-implicit-function-declaration\
          -fno-tree-loop-distribute-patterns -march=rv64imac_zicsr -mabi=lp64 \
          -I$(WOLFSSL_INCLUDE)

# Put wolfssl library AFTER your object files, and use --whole-archive if needed
LDFLAGS := -static -nostdlib -nostartfiles -march=rv64imac -mabi=lp64 \
           -L$(WOLFSSL_LIB) -Wl,--whole-archive -lwolfssl -Wl,--no-whole-archive -lgcc -ffunction-sections -fdata-sections -Wl,--gc-sections
CFLAGS+= -I $(bmarkdir)/include -I.
PROGRAMS := sha3-rocc sha3-sw wolfssl_test wolfssl_aes chachapoly_test ascon_test chachapoly_global_heap string_test chachapoly_wolfssl_official ascon_official_replica ascon_diagnostic hpke_official_replica hpke_config_check curve25519_init_test \
            drbg_memory_test test_aes test_aes_hkdf_rng test_curve25519_component_timing test_hpke_open_timing test_curve25519_timing gcd hello ascon

objs := crt.o syscalls.o ../src/driver/chacha/chacha.o ../src/driver/poly/poly.o ../src/driver/x25519/x25519.o ../src/driver/aes_gcm/aes_gcm.o ../src/driver/hmac_sha/hmac_sha.o ../src/driver/ascon/ascon.o
ldscript := link.ld

include $(bmarkdir)/../common.mk