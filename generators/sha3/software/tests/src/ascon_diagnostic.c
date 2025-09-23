#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "compiler.h"
#include <wolfssl/options.h>

// Try to include ASCON headers and see what's available
#ifdef HAVE_ASCON
#include <wolfssl/wolfcrypt/ascon.h>
#define ASCON_AVAILABLE 1
#else
#define ASCON_AVAILABLE 0
#endif

// Test what constants are defined
void check_ascon_defines(void)
{
    printf("=== ASCON Build Configuration Check ===\n");
    
#ifdef HAVE_ASCON
    printf("✓ HAVE_ASCON is defined\n");
#else
    printf("✗ HAVE_ASCON is NOT defined\n");
#endif

    
    // Check if constants are defined
#ifdef ASCON_HASH256_SZ
    printf("✓ ASCON_HASH256_SZ = %d\n", ASCON_HASH256_SZ);
#else
    printf("✗ ASCON_HASH256_SZ not defined\n");
#endif

#ifdef ASCON_AEAD128_KEY_SZ
    printf("✓ ASCON_AEAD128_KEY_SZ = %d\n", ASCON_AEAD128_KEY_SZ);
#else
    printf("✗ ASCON_AEAD128_KEY_SZ not defined\n");
#endif

#ifdef ASCON_AEAD128_NONCE_SZ
    printf("✓ ASCON_AEAD128_NONCE_SZ = %d\n", ASCON_AEAD128_NONCE_SZ);
#else
    printf("✗ ASCON_AEAD128_NONCE_SZ not defined\n");
#endif

#ifdef ASCON_AEAD128_TAG_SZ
    printf("✓ ASCON_AEAD128_TAG_SZ = %d\n", ASCON_AEAD128_TAG_SZ);
#else
    printf("✗ ASCON_AEAD128_TAG_SZ not defined\n");
#endif

#else
    printf("✗ ASCON headers could not be included\n");
#endif
}

void test_ascon_function_availability(void)
{
    printf("\n=== ASCON Function Availability Test ===\n");
    
#if ASCON_AVAILABLE
    // Test if we can call the _New functions (they might fail but shouldn't crash)
    printf("Testing wc_AsconHash256_New()...\n");
    wc_AsconHash256* hash = wc_AsconHash256_New();
    if (hash != NULL) {
        printf("✓ wc_AsconHash256_New() returned valid pointer\n");
        wc_AsconHash256_Free(hash);
    } else {
        printf("✗ wc_AsconHash256_New() returned NULL\n");
    }
    
    printf("Testing wc_AsconAEAD128_New()...\n");
    wc_AsconAEAD128* aead = wc_AsconAEAD128_New();
    if (aead != NULL) {
        printf("✓ wc_AsconAEAD128_New() returned valid pointer\n");
        wc_AsconAEAD128_Free(aead);
    } else {
        printf("✗ wc_AsconAEAD128_New() returned NULL\n");
    }
#else
    printf("ASCON not available - skipping function tests\n");
#endif
}

void test_simple_ascon_operations(void)
{
    printf("\n=== Simple ASCON Operation Test ===\n");
    
#if ASCON_AVAILABLE
    // Try the most basic operations
    wc_AsconHash256* hash = wc_AsconHash256_New();
    if (hash != NULL) {
        printf("Testing basic hash operations...\n");
        
        int ret = wc_AsconHash256_Init(hash);
        printf("wc_AsconHash256_Init() returned: %d\n", ret);
        
        if (ret == 0) {
            byte output[32];
            ret = wc_AsconHash256_Final(hash, output);
            printf("wc_AsconHash256_Final() returned: %d\n", ret);
            
            if (ret == 0) {
                printf("✓ Basic ASCON Hash256 operations work!\n");
                printf("Empty message hash: ");
                for (int i = 0; i < 32; i++) {
                    printf("%02x", output[i]);
                }
                printf("\n");
            }
        }
        
        wc_AsconHash256_Free(hash);
    } else {
        printf("Cannot test operations - wc_AsconHash256_New() failed\n");
    }
#else
    printf("ASCON not available - skipping operation tests\n");
#endif
}

void check_wolfssl_version_info(void)
{
    printf("\n=== WolfSSL Version Information ===\n");
    
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

    // Check other crypto that should be available
    printf("\nOther crypto availability:\n");
    
#ifdef HAVE_CHACHA
    printf("✓ HAVE_CHACHA\n");
#else
    printf("✗ HAVE_CHACHA\n");
#endif

#ifdef HAVE_POLY1305
    printf("✓ HAVE_POLY1305\n");
#else
    printf("✗ HAVE_POLY1305\n");
#endif

#ifdef HAVE_AES
    printf("✓ HAVE_AES\n");
#else
    printf("✗ HAVE_AES\n");
#endif

#ifdef HAVE_SHA256
    printf("✓ HAVE_SHA256\n");
#else
    printf("✗ HAVE_SHA256\n");
#endif
}

int main(void)
{
    printf("ASCON Availability Diagnostic Test\n");
    printf("==================================\n");
    
    unsigned long start = rdcycle();
    
    check_ascon_defines();
    check_wolfssl_version_info(); 
    test_ascon_function_availability();
    test_simple_ascon_operations();
    
    unsigned long end = rdcycle();
    
    printf("\n==================================\n");
    printf("Diagnostic completed in %lu cycles\n", end - start);
    
    printf("\n=== Summary ===\n");
#if ASCON_AVAILABLE
    printf("ASCON appears to be compiled in but functions are failing\n");
    printf("Possible issues:\n");
    printf("1. WolfSSL built without ASCON support\n");
    printf("2. Memory allocation issues\n");
    printf("3. ASCON implementation not included in this build\n");
    printf("\nRecommendation: Check your WolfSSL build configuration\n");
#else
    printf("ASCON is NOT available in this WolfSSL build\n");
    printf("To enable ASCON, rebuild WolfSSL with:\n");
    printf("  --enable-ascon  or  -DWOLFSSL_ASCON\n");
#endif
    
    return 0;
}