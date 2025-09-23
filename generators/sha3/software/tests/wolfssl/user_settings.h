/* user_settings.h - wolfSSL configuration for RISC-V with HASHDRBG */
#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* Enable user settings */
#define WOLFSSL_USER_SETTINGS

/* Basic wolfSSL settings for your configuration */
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define WOLFSSL_ASCON_AEAD
#define WOLFSSL_HAVE_HPKE
#define HAVE_KYBER
#define HAVE_DILITHIUM
#define HAVE_AEAD
#define WOLFSSL_PSK
#define WOLFSSL_NO_FILESYSTEM
#define WOLFSSL_NO_STDIO
#define WOLFSSL_NO_DEV_RANDOM
#define WOLFSSL_NO_SIG_WRAPPER
#define WOLFSSL_NO_ASYNC
#define NO_MAIN_DRIVER
#define WOLFSSL_USER_IO
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define WOLFSSL_NO_MALLOC
#define WOLFSSL_STATIC_MEMORY
#define HAVE_HKDF
#define HAVE_HMAC
#define HAVE_ECC
#define HAVE_ECDH
#define HAVE_ECC_ENCRYPT
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define HAVE_CURVE25519
#define HAVE_CURVE448
#define HAVE_ECC_SECP256R1
#define HAVE_ECC_SECP384R1
#define HAVE_ECC_SECP521R1
#define WOLFSSL_SP_MATH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_MATH_ECC
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_NO_SIGNAL
#define NO_DEV_RANDOM

/* Additional settings for embedded RISC-V */
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* Disable unused features to save space */
#define NO_DES3
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PWDBASED
#define NO_OLD_TLS

/* ------------------------------------------------------------------------- */
/* RNG Configuration */
/* ------------------------------------------------------------------------- */
#if 0
    /* Option 1: Bypass P-RNG and use only HW RNG */
    #define CUSTOM_RAND_TYPE      unsigned int
    extern int my_rng_gen_block(unsigned char* output, unsigned int sz);
    #undef  CUSTOM_RAND_GENERATE_BLOCK
    #define CUSTOM_RAND_GENERATE_BLOCK  my_rng_gen_block
#else
    /* Option 2: HASHDRBG with custom seed source (RECOMMENDED) */
    #define HAVE_HASHDRBG
    
    /* Custom seed configuration */
    #define CUSTOM_RAND_TYPE      unsigned int
    extern unsigned int my_rng_seed_gen(void);
    #undef  CUSTOM_RAND_GENERATE
    #define CUSTOM_RAND_GENERATE  my_rng_seed_gen
    
    /* HASHDRBG configuration */
    #define WC_RESEED_INTERVAL 10000  /* Reseed every 10000 requests */
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */