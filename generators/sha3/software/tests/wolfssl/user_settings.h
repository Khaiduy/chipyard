/* user_settings.h - wolfSSL configuration for RISC-V with HASHDRBG */
#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* Enable user settings */
#define WOLFSSL_USER_SETTINGS

/* Minimal wolfSSL settings for HPKE + ASCON */
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define WOLFSSL_ASCON_AEAD
#define HAVE_ASCON
#define WOLFSSL_HAVE_HPKE
#define HAVE_AEAD
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
#define WOLFSSL_SHA256              // Only SHA256
#define HAVE_CURVE25519             // Only Curve25519
#define HAVE_ECC_SECP256R1          // Only secp256r1
#define WOLFSSL_SP_MATH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_MATH_ECC
#define WOLFSSL_NO_SIGNAL
#define NO_DEV_RANDOM

/* Additional settings for embedded RISC-V */
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ===== SIZE OPTIMIZATION: Disable unused features ===== */
#define NO_DES3
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PWDBASED
#define NO_OLD_TLS
#define NO_RSA                      // Remove RSA entirely
#define NO_DH                       // Remove Diffie-Hellman
#define WOLFSSL_NO_ASN              // Disable ASN.1 parsing  
#define NO_CERTS                    // Disable certificate support
#define NO_SESSION_CACHE            // Disable TLS session cache
#define WOLFSSL_SP_SMALL            // Use smaller SP math
#define NO_CODING                   // Disable base64/hex encoding
#define NO_INLINE                   // Disable function inlining

/* Remove unused crypto algorithms */
#define NO_AES_192                  // Only AES-128 and AES-256
#define NO_AES_CBC                  // Only GCM mode
#define NO_AES_CFB
#define NO_AES_OFB
#define NO_CHACHA
#define NO_POLY1305

/* Remove unused ECC curves */
#define NO_ECC_DHE
#define NO_ECC_SIGN
#define NO_ECC_VERIFY

/* Remove post-quantum and advanced features */
#define NO_PSK
#define NO_ERROR_STRINGS            // Remove error string messages

/* Reduce static memory */
#define WOLFSSL_STATIC_MEM_SIZE 16384  // Reduce from 65536 to 16KB

/* RNG Configuration */
#define HAVE_HASHDRBG
#define CUSTOM_RAND_TYPE      unsigned int
extern unsigned int my_rng_seed_gen(void);
#undef  CUSTOM_RAND_GENERATE
#define CUSTOM_RAND_GENERATE  my_rng_seed_gen
#define WC_RESEED_INTERVAL 10000

#endif /* WOLFSSL_USER_SETTINGS_H */