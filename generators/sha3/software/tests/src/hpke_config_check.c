#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "compiler.h"
#include <wolfssl/options.h>

// Try to include all HPKE-related headers
#ifdef HAVE_HPKE
#include <wolfssl/wolfcrypt/hpke.h>
#define HPKE_HEADER_AVAILABLE 1
#else
#define HPKE_HEADER_AVAILABLE 0
#endif

// Include other crypto headers for dependency checking
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

void check_hpke_main_defines(void)
{
    printf("=== HPKE Main Configuration Defines ===\n");
    
#ifdef HAVE_HPKE
    printf("✓ HAVE_HPKE is defined\n");
#else
    printf("✗ HAVE_HPKE is NOT defined\n");
#endif

#ifdef WOLFSSL_HPKE
    printf("✓ WOLFSSL_HPKE is defined\n");
#else
    printf("✗ WOLFSSL_HPKE is NOT defined\n");
#endif

    if (HPKE_HEADER_AVAILABLE) {
        printf("✓ HPKE headers can be included\n");
    } else {
        printf("✗ HPKE headers cannot be included\n");
    }
}

void check_hpke_crypto_dependencies(void)
{
    printf("\n=== HPKE Crypto Dependencies ===\n");
    
    // ECC Support (required for P256, P384, P521)
#ifdef HAVE_ECC
    printf("✓ HAVE_ECC is defined\n");
#else
    printf("✗ HAVE_ECC is NOT defined\n");
#endif

    // Curve25519 Support (required for X25519)
#ifdef HAVE_CURVE25519
    printf("✓ HAVE_CURVE25519 is defined\n");
#else
    printf("✗ HAVE_CURVE25519 is NOT defined\n");
#endif

    // Curve448 Support (for future X448)
#ifdef HAVE_CURVE448
    printf("✓ HAVE_CURVE448 is defined\n");
#else
    printf("✗ HAVE_CURVE448 is NOT defined\n");
#endif

    // AES GCM Support (required for AEAD)
#ifdef HAVE_AESGCM
    printf("✓ HAVE_AESGCM is defined\n");
#else
    printf("✗ HAVE_AESGCM is NOT defined\n");
#endif

    // AES Support (basic requirement)
#ifdef HAVE_AES
    printf("✓ HAVE_AES is defined\n");
#else
    printf("✗ HAVE_AES is NOT defined\n");
#endif

    // HKDF Support (required for key derivation)
#ifdef HAVE_HKDF
    printf("✓ HAVE_HKDF is defined\n");
#else
    printf("✗ HAVE_HKDF is NOT defined\n");
#endif

    // HMAC Support (required for HKDF)
#ifdef HAVE_HMAC
    printf("✓ HAVE_HMAC is defined\n");
#else
    printf("✗ HAVE_HMAC is NOT defined\n");
#endif
}

void check_hpke_hash_support(void)
{
    printf("\n=== HPKE Hash Algorithm Support ===\n");
    
    // SHA256 (required for most KEM/KDF combinations)
#ifdef WOLFSSL_SHA224
    printf("✓ WOLFSSL_SHA224 is defined\n");
#else
    printf("✗ WOLFSSL_SHA224 is NOT defined\n");
#endif

#ifndef NO_SHA256
    printf("✓ SHA256 is available (NO_SHA256 not defined)\n");
#else
    printf("✗ SHA256 is NOT available (NO_SHA256 is defined)\n");
#endif

    // SHA384 (required for P384 combinations)
#ifdef WOLFSSL_SHA384
    printf("✓ WOLFSSL_SHA384 is defined\n");
#else
    printf("✗ WOLFSSL_SHA384 is NOT defined\n");
#endif

    // SHA512 (required for P521 combinations)
#ifdef WOLFSSL_SHA512
    printf("✓ WOLFSSL_SHA512 is defined\n");
#else
    printf("✗ WOLFSSL_SHA512 is NOT defined\n");
#endif
}

void check_hpke_curve_support(void)
{
    printf("\n=== HPKE Curve Support ===\n");
    
    // Individual ECC curves
#ifdef ECC_SECP256R1
    printf("✓ ECC_SECP256R1 is defined\n");
#else
    printf("✗ ECC_SECP256R1 is NOT defined\n");
#endif

#ifdef ECC_SECP384R1
    printf("✓ ECC_SECP384R1 is defined\n");
#else
    printf("✗ ECC_SECP384R1 is NOT defined\n");
#endif

#ifdef ECC_SECP521R1
    printf("✓ ECC_SECP521R1 is defined\n");
#else
    printf("✗ ECC_SECP521R1 is NOT defined\n");
#endif

    // Curve25519 specifics
#ifdef CURVE25519_KEYSIZE
    printf("✓ CURVE25519_KEYSIZE is defined (%d)\n", CURVE25519_KEYSIZE);
#else
    printf("✗ CURVE25519_KEYSIZE is NOT defined\n");
#endif

#ifdef CURVE25519_PUB_KEY_SIZE
    printf("✓ CURVE25519_PUB_KEY_SIZE is defined (%d)\n", CURVE25519_PUB_KEY_SIZE);
#else
    printf("✗ CURVE25519_PUB_KEY_SIZE is NOT defined\n");
#endif
}

void check_hpke_constants(void)
{
    printf("\n=== HPKE Constants and Sizes ===\n");
    
#if HPKE_HEADER_AVAILABLE
    // KEM algorithm constants
#ifdef DHKEM_P256_HKDF_SHA256
    printf("✓ DHKEM_P256_HKDF_SHA256 = %d\n", DHKEM_P256_HKDF_SHA256);
#else
    printf("✗ DHKEM_P256_HKDF_SHA256 is NOT defined\n");
#endif

#ifdef DHKEM_P384_HKDF_SHA384
    printf("✓ DHKEM_P384_HKDF_SHA384 = %d\n", DHKEM_P384_HKDF_SHA384);
#else
    printf("✗ DHKEM_P384_HKDF_SHA384 is NOT defined\n");
#endif

#ifdef DHKEM_P521_HKDF_SHA512
    printf("✓ DHKEM_P521_HKDF_SHA512 = %d\n", DHKEM_P521_HKDF_SHA512);
#else
    printf("✗ DHKEM_P521_HKDF_SHA512 is NOT defined\n");
#endif

#ifdef DHKEM_X25519_HKDF_SHA256
    printf("✓ DHKEM_X25519_HKDF_SHA256 = %d\n", DHKEM_X25519_HKDF_SHA256);
#else
    printf("✗ DHKEM_X25519_HKDF_SHA256 is NOT defined\n");
#endif

    // KDF algorithm constants
#ifdef HKDF_SHA256
    printf("✓ HKDF_SHA256 = %d\n", HKDF_SHA256);
#else
    printf("✗ HKDF_SHA256 is NOT defined\n");
#endif

#ifdef HKDF_SHA384
    printf("✓ HKDF_SHA384 = %d\n", HKDF_SHA384);
#else
    printf("✗ HKDF_SHA384 is NOT defined\n");
#endif

#ifdef HKDF_SHA512
    printf("✓ HKDF_SHA512 = %d\n", HKDF_SHA512);
#else
    printf("✗ HKDF_SHA512 is NOT defined\n");
#endif

    // AEAD algorithm constants
#ifdef HPKE_AES_128_GCM
    printf("✓ HPKE_AES_128_GCM = %d\n", HPKE_AES_128_GCM);
#else
    printf("✗ HPKE_AES_128_GCM is NOT defined\n");
#endif

#ifdef HPKE_AES_256_GCM
    printf("✓ HPKE_AES_256_GCM = %d\n", HPKE_AES_256_GCM);
#else
    printf("✗ HPKE_AES_256_GCM is NOT defined\n");
#endif

    // Size constants
#ifdef HPKE_Nn_MAX
    printf("✓ HPKE_Nn_MAX = %d\n", HPKE_Nn_MAX);
#else
    printf("✗ HPKE_Nn_MAX is NOT defined\n");
#endif

#ifdef HPKE_Npk_MAX
    printf("✓ HPKE_Npk_MAX = %d\n", HPKE_Npk_MAX);
#else
    printf("✗ HPKE_Npk_MAX is NOT defined\n");
#endif

#ifdef HPKE_Ndh_MAX
    printf("✓ HPKE_Ndh_MAX = %d\n", HPKE_Ndh_MAX);
#else
    printf("✗ HPKE_Ndh_MAX is NOT defined\n");
#endif

#ifdef HPKE_Nsecret_MAX
    printf("✓ HPKE_Nsecret_MAX = %d\n", HPKE_Nsecret_MAX);
#else
    printf("✗ HPKE_Nsecret_MAX is NOT defined\n");
#endif

#else
    printf("Cannot check HPKE constants - headers not available\n");
#endif
}

void check_hpke_supported_arrays(void)
{
    printf("\n=== HPKE Supported Algorithm Arrays ===\n");
    
#if HPKE_HEADER_AVAILABLE
#ifdef HPKE_SUPPORTED_KEM_LEN
    printf("✓ HPKE_SUPPORTED_KEM_LEN = %d\n", HPKE_SUPPORTED_KEM_LEN);
#else
    printf("✗ HPKE_SUPPORTED_KEM_LEN is NOT defined\n");
#endif

#ifdef HPKE_SUPPORTED_KDF_LEN
    printf("✓ HPKE_SUPPORTED_KDF_LEN = %d\n", HPKE_SUPPORTED_KDF_LEN);
#else
    printf("✗ HPKE_SUPPORTED_KDF_LEN is NOT defined\n");
#endif

#ifdef HPKE_SUPPORTED_AEAD_LEN
    printf("✓ HPKE_SUPPORTED_AEAD_LEN = %d\n", HPKE_SUPPORTED_AEAD_LEN);
#else
    printf("✗ HPKE_SUPPORTED_AEAD_LEN is NOT defined\n");
#endif
#else
    printf("Cannot check supported arrays - headers not available\n");
#endif
}

void check_compilation_requirements(void)
{
    printf("\n=== HPKE Compilation Requirements Check ===\n");
    
    // Based on the source code, HPKE requires:
    // #if defined(HAVE_HPKE) && (defined(HAVE_ECC) || defined(HAVE_CURVE25519)) && defined(HAVE_AESGCM)
    
    printf("HPKE compilation condition:\n");
    printf("  HAVE_HPKE && (HAVE_ECC || HAVE_CURVE25519) && HAVE_AESGCM\n\n");
    
    int have_hpke = 0, have_curves = 0, have_aesgcm = 0;
    
#ifdef HAVE_HPKE
    printf("✓ HAVE_HPKE: YES\n");
    have_hpke = 1;
#else
    printf("✗ HAVE_HPKE: NO\n");
#endif

#if defined(HAVE_ECC) || defined(HAVE_CURVE25519)
    printf("✓ Curve support (HAVE_ECC || HAVE_CURVE25519): YES\n");
    have_curves = 1;
#ifdef HAVE_ECC
    printf("  - ECC curves available\n");
#endif
#ifdef HAVE_CURVE25519
    printf("  - Curve25519 available\n");
#endif
#else
    printf("✗ Curve support (HAVE_ECC || HAVE_CURVE25519): NO\n");
#endif

#ifdef HAVE_AESGCM
    printf("✓ HAVE_AESGCM: YES\n");
    have_aesgcm = 1;
#else
    printf("✗ HAVE_AESGCM: NO\n");
#endif

    printf("\n--- OVERALL HPKE COMPILATION STATUS ---\n");
    if (have_hpke && have_curves && have_aesgcm) {
        printf("🎉 HPKE SHOULD BE COMPILED AND AVAILABLE!\n");
        printf("All required dependencies are met.\n");
    } else {
        printf("❌ HPKE IS NOT COMPILED\n");
        printf("Missing requirements:\n");
        if (!have_hpke) printf("  - HAVE_HPKE not defined\n");
        if (!have_curves) printf("  - No curve support (need HAVE_ECC or HAVE_CURVE25519)\n");
        if (!have_aesgcm) printf("  - HAVE_AESGCM not defined\n");
    }
}

void check_wolfssl_version_and_config(void)
{
    printf("\n=== WolfSSL Version and Configuration ===\n");
    
#ifdef LIBWOLFSSL_VERSION_STRING
    printf("WolfSSL version: %s\n", LIBWOLFSSL_VERSION_STRING);
#else
    printf("WolfSSL version string not available\n");
#endif

#ifdef WOLFSSL_VERSION
    printf("WolfSSL version number: %d\n", WOLFSSL_VERSION);
#else
    printf("WolfSSL version number not available\n");
#endif

    // Check for common configuration flags
    printf("\nCommon WolfSSL build configurations:\n");
    
#ifdef WOLFSSL_SMALL_STACK
    printf("✓ WOLFSSL_SMALL_STACK is defined\n");
#else
    printf("✗ WOLFSSL_SMALL_STACK is NOT defined\n");
#endif

#ifdef SINGLE_THREADED
    printf("✓ SINGLE_THREADED is defined\n");
#else
    printf("✗ SINGLE_THREADED is NOT defined\n");
#endif

#ifdef NO_FILESYSTEM
    printf("✓ NO_FILESYSTEM is defined\n");
#else
    printf("✗ NO_FILESYSTEM is NOT defined\n");
#endif

#ifdef WOLFSSL_USER_SETTINGS
    printf("✓ WOLFSSL_USER_SETTINGS is defined\n");
#else
    printf("✗ WOLFSSL_USER_SETTINGS is NOT defined\n");
#endif
}



int main(void)
{
    printf("WolfSSL HPKE Configuration Checker\n");
    printf("==================================\n");
    
    unsigned long start = rdcycle();
    
    check_hpke_main_defines();
    check_hpke_crypto_dependencies();
    check_hpke_hash_support();
    check_hpke_curve_support();
    check_hpke_constants();
    check_hpke_supported_arrays();
    check_compilation_requirements();
    check_wolfssl_version_and_config();
    
    unsigned long end = rdcycle();
    
    printf("\n==================================\n");
    printf("Configuration check completed in %lu cycles\n", end - start);
    
    printf("\n=== SUMMARY ===\n");
#if HPKE_HEADER_AVAILABLE && defined(HAVE_HPKE) && (defined(HAVE_ECC) || defined(HAVE_CURVE25519)) && defined(HAVE_AESGCM)
    printf("🎉 HPKE appears to be properly configured!\n");
    printf("You should be able to use HPKE functionality.\n");
    printf("\nRecommended next steps:\n");
    printf("1. Run the official HPKE test replica\n");
    printf("2. Test different cipher suites\n");
    printf("3. Verify performance on RISC-V\n");
#else
    printf("❌ HPKE is NOT properly configured\n");
    printf("\nTo enable HPKE, ensure your WolfSSL build includes:\n");
    printf("  --enable-hpke (or -DHAVE_HPKE)\n");
    printf("  --enable-ecc (or -DHAVE_ECC)\n");
    printf("  --enable-aesgcm (or -DHAVE_AESGCM)\n");
    printf("  --enable-hkdf (or -DHAVE_HKDF)\n");
    printf("  Proper hash support (SHA256/384/512)\n");
    printf("\nOptional for X25519 support:\n");
    printf("  --enable-curve25519 (or -DHAVE_CURVE25519)\n");
#endif
    
    return 0;
}