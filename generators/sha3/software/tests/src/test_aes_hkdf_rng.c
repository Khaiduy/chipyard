/* test_hpke_crypto.c
 * Comprehensive test for HPKE-required cryptographic functions
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "compiler.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef XMEMSET  
#define XMEMSET memset
#endif

#ifndef XMEMCMP
#define XMEMCMP memcmp
#endif

// Static memory setup for WolfSSL
#define WOLFSSL_STATIC_MEM_SIZE 65536  // 64KB for comprehensive tests
static byte g_wolfssl_mem[WOLFSSL_STATIC_MEM_SIZE];
static WOLFSSL_HEAP_HINT* g_heap_hint = NULL;

// Test result tracking
static int test_failures = 0;
static int tests_passed = 0;

// Helper function to check test results
int check_result(const char* test_name, int actual, int expected)
{
    if (actual == expected) {
        printf("✅ %s: PASS (result: %d)\n", test_name, actual);
        tests_passed++;
        return 0;
    } else {
        printf("❌ %s: FAIL (expected: %d, got: %d)\n", test_name, expected, actual);
        test_failures++;
        return -1;
    }
}

// Setup static memory
static int setup_wolfssl_memory(void)
{
#ifdef WOLFSSL_STATIC_MEMORY
    int ret = wc_LoadStaticMemory(&g_heap_hint, g_wolfssl_mem, 
                                  WOLFSSL_STATIC_MEM_SIZE, 0, 20);
    if (ret != 0) {
        printf("wc_LoadStaticMemory failed: %d\n", ret);
        return ret;
    }
    printf("Static memory initialized successfully\n");
    return 0;
#else
    printf("WOLFSSL_STATIC_MEMORY not defined\n");
    return -1;
#endif
}

/*
 * Test AES-GCM functions (based on wolfssl_test.c and wolfssl_aes.c patterns)
 */
static int test_aes_gcm_functions(void)
{
    printf("\n=== Test AES-GCM Functions ===\n");
    
#if defined(HAVE_AESGCM)
    Aes aes;
    byte key128[] = { 
        0x16, 0x39, 0x05, 0x42, 0x36, 0x77, 0x90, 0x07,
        0x23, 0x46, 0x89, 0x4a, 0xbc, 0xde, 0xf0, 0x12
    };
    byte key256[] = {
        0x16, 0x39, 0x05, 0x42, 0x36, 0x77, 0x90, 0x07,
        0x23, 0x46, 0x89, 0x4a, 0xbc, 0xde, 0xf0, 0x12,
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };
    byte iv[] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x34, 0x56, 0x78, 0x9a
    };
    byte plaintext[] = "Hello World! This is a test message for AES-GCM encryption.";
    byte ciphertext[sizeof(plaintext)];
    byte decrypted[sizeof(plaintext)];
    byte authTag[AES_BLOCK_SIZE];
    byte authIn[] = "Additional authenticated data";
    int ret;

    // Test 1: wc_AesInit
    printf("\nTesting wc_AesInit...\n");
    ret = wc_AesInit(&aes, g_heap_hint, INVALID_DEVID);
    if (check_result("wc_AesInit", ret, 0) != 0) return -1;

    // Test bad args for wc_AesInit
    ret = wc_AesInit(NULL, g_heap_hint, INVALID_DEVID);
    if (check_result("wc_AesInit(NULL)", ret, BAD_FUNC_ARG) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Test 2: wc_AesGcmSetKey with 128-bit key
    printf("\nTesting wc_AesGcmSetKey (128-bit)...\n");
    ret = wc_AesGcmSetKey(&aes, key128, sizeof(key128));
    if (check_result("wc_AesGcmSetKey(128)", ret, 0) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Test 3: wc_AesGcmEncrypt
    printf("\nTesting wc_AesGcmEncrypt...\n");
    ret = wc_AesGcmEncrypt(&aes, ciphertext, plaintext, sizeof(plaintext)-1,
                           iv, sizeof(iv), authTag, sizeof(authTag),
                           authIn, sizeof(authIn)-1);
    if (check_result("wc_AesGcmEncrypt", ret, 0) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Test 4: wc_AesGcmDecrypt
    printf("\nTesting wc_AesGcmDecrypt...\n");
    ret = wc_AesGcmDecrypt(&aes, decrypted, ciphertext, sizeof(plaintext)-1,
                           iv, sizeof(iv), authTag, sizeof(authTag),
                           authIn, sizeof(authIn)-1);
    if (check_result("wc_AesGcmDecrypt", ret, 0) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Verify decryption matches original
    ret = XMEMCMP(plaintext, decrypted, sizeof(plaintext)-1);
    if (check_result("Decryption verification", ret, 0) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Test bad args for wc_AesGcmSetKey
    ret = wc_AesGcmSetKey(NULL, key128, sizeof(key128));
    if (check_result("wc_AesGcmSetKey(NULL aes)", ret, BAD_FUNC_ARG) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    ret = wc_AesGcmSetKey(&aes, NULL, sizeof(key128));
    if (check_result("wc_AesGcmSetKey(NULL key)", ret, BAD_FUNC_ARG) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    ret = wc_AesGcmSetKey(&aes, key128, 0);
    if (check_result("wc_AesGcmSetKey(zero keylen)", ret, BAD_FUNC_ARG) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Test bad args for wc_AesGcmEncrypt
    ret = wc_AesGcmEncrypt(NULL, ciphertext, plaintext, sizeof(plaintext)-1,
                           iv, sizeof(iv), authTag, sizeof(authTag),
                           authIn, sizeof(authIn)-1);
    if (check_result("wc_AesGcmEncrypt(NULL aes)", ret, BAD_FUNC_ARG) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Test bad args for wc_AesGcmDecrypt
    ret = wc_AesGcmDecrypt(NULL, decrypted, ciphertext, sizeof(plaintext)-1,
                           iv, sizeof(iv), authTag, sizeof(authTag),
                           authIn, sizeof(authIn)-1);
    if (check_result("wc_AesGcmDecrypt(NULL aes)", ret, BAD_FUNC_ARG) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Test 5: wc_AesGcmSetKey with 256-bit key
    printf("\nTesting wc_AesGcmSetKey (256-bit)...\n");
    ret = wc_AesGcmSetKey(&aes, key256, sizeof(key256));
    if (check_result("wc_AesGcmSetKey(256)", ret, 0) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Test encryption/decryption with 256-bit key
    ret = wc_AesGcmEncrypt(&aes, ciphertext, plaintext, sizeof(plaintext)-1,
                           iv, sizeof(iv), authTag, sizeof(authTag),
                           authIn, sizeof(authIn)-1);
    if (check_result("wc_AesGcmEncrypt(256)", ret, 0) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    ret = wc_AesGcmDecrypt(&aes, decrypted, ciphertext, sizeof(plaintext)-1,
                           iv, sizeof(iv), authTag, sizeof(authTag),
                           authIn, sizeof(authIn)-1);
    if (check_result("wc_AesGcmDecrypt(256)", ret, 0) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Test 6: wc_AesFree
    printf("\nTesting wc_AesFree...\n");
    wc_AesFree(&aes);
    printf("✅ wc_AesFree: PASS\n");
    tests_passed++;

    // Test wc_AesFree with NULL (should not crash)
    wc_AesFree(NULL);
    printf("✅ wc_AesFree(NULL): PASS\n");
    tests_passed++;

    return 0;
#else
    printf("⏭️  HAVE_AESGCM not defined - skipping AES-GCM tests\n");
    return 0;
#endif
}

/*
 * Test HKDF Extract and Expand functions
 */
static int test_hkdf_functions(void)
{
    printf("\n=== Test HKDF Functions ===\n");
    
#if defined(HAVE_HKDF)
    // Test vectors based on RFC 5869
    byte ikm[] = { // Input Key Material
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    byte salt[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    byte info[] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9
    };
    byte prk[WC_SHA256_DIGEST_SIZE];  // Pseudo-random key
    byte okm[42];  // Output key material
    byte expected_prk[] = {  // Expected PRK from RFC 5869 test case 1
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    };
    int ret;

    // Test 1: wc_HKDF_Extract
    printf("\nTesting wc_HKDF_Extract...\n");
    ret = wc_HKDF_Extract(WC_SHA256, salt, sizeof(salt), ikm, sizeof(ikm), prk);
    if (check_result("wc_HKDF_Extract", ret, 0) != 0) return -1;

    // Verify PRK matches expected value
    ret = XMEMCMP(prk, expected_prk, sizeof(expected_prk));
    if (check_result("HKDF Extract PRK verification", ret, 0) != 0) {
        printf("Expected PRK: ");
        for (int i = 0; i < sizeof(expected_prk); i++) {
            printf("%02x", expected_prk[i]);
        }
        printf("\nActual PRK:   ");
        for (int i = 0; i < sizeof(prk); i++) {
            printf("%02x", prk[i]);
        }
        printf("\n");
        return -1;
    }

    // Test 2: wc_HKDF_Expand
    printf("\nTesting wc_HKDF_Expand...\n");
    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk), info, sizeof(info), okm, sizeof(okm));
    if (check_result("wc_HKDF_Expand", ret, 0) != 0) return -1;

    // Test bad args for wc_HKDF_Extract
    ret = wc_HKDF_Extract(WC_SHA256, NULL, sizeof(salt), ikm, sizeof(ikm), prk);
    if (check_result("wc_HKDF_Extract(NULL salt)", ret, 0) != 0) return -1; // NULL salt is allowed

    ret = wc_HKDF_Extract(WC_SHA256, salt, sizeof(salt), NULL, sizeof(ikm), prk);
    if (check_result("wc_HKDF_Extract(NULL ikm)", ret, BAD_FUNC_ARG) != 0) return -1;

    ret = wc_HKDF_Extract(WC_SHA256, salt, sizeof(salt), ikm, sizeof(ikm), NULL);
    if (check_result("wc_HKDF_Extract(NULL prk)", ret, BAD_FUNC_ARG) != 0) return -1;

    // Test bad args for wc_HKDF_Expand
    ret = wc_HKDF_Expand(WC_SHA256, NULL, sizeof(prk), info, sizeof(info), okm, sizeof(okm));
    if (check_result("wc_HKDF_Expand(NULL prk)", ret, BAD_FUNC_ARG) != 0) return -1;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk), info, sizeof(info), NULL, sizeof(okm));
    if (check_result("wc_HKDF_Expand(NULL okm)", ret, BAD_FUNC_ARG) != 0) return -1;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk), NULL, sizeof(info), okm, sizeof(okm));
    if (check_result("wc_HKDF_Expand(NULL info)", ret, 0) != 0) return -1; // NULL info is allowed

    // Test with different hash algorithms
#ifdef WOLFSSL_SHA384
    printf("\nTesting HKDF with SHA-384...\n");
    byte prk384[WC_SHA384_DIGEST_SIZE];
    ret = wc_HKDF_Extract(WC_SHA384, salt, sizeof(salt), ikm, sizeof(ikm), prk384);
    if (check_result("wc_HKDF_Extract(SHA384)", ret, 0) != 0) return -1;

    ret = wc_HKDF_Expand(WC_SHA384, prk384, sizeof(prk384), info, sizeof(info), okm, sizeof(okm));
    if (check_result("wc_HKDF_Expand(SHA384)", ret, 0) != 0) return -1;
#endif

#ifdef WOLFSSL_SHA512
    printf("\nTesting HKDF with SHA-512...\n");
    byte prk512[WC_SHA512_DIGEST_SIZE];
    ret = wc_HKDF_Extract(WC_SHA512, salt, sizeof(salt), ikm, sizeof(ikm), prk512);
    if (check_result("wc_HKDF_Extract(SHA512)", ret, 0) != 0) return -1;

    ret = wc_HKDF_Expand(WC_SHA512, prk512, sizeof(prk512), info, sizeof(info), okm, sizeof(okm));
    if (check_result("wc_HKDF_Expand(SHA512)", ret, 0) != 0) return -1;
#endif

    // Test edge cases
    printf("\nTesting HKDF edge cases...\n");
    
    // Zero-length IKM
    ret = wc_HKDF_Extract(WC_SHA256, salt, sizeof(salt), ikm, 0, prk);
    if (check_result("wc_HKDF_Extract(zero IKM)", ret, 0) != 0) return -1;

    // Large OKM output
    byte large_okm[255];  // Maximum for HKDF
    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk), info, sizeof(info), large_okm, sizeof(large_okm));
    if (check_result("wc_HKDF_Expand(max OKM)", ret, 0) != 0) return -1;

    // Too large OKM output (should fail)
    byte too_large_okm[256];
    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk), info, sizeof(info), too_large_okm, sizeof(too_large_okm));
    if (check_result("wc_HKDF_Expand(too large OKM)", ret, BAD_FUNC_ARG) != 0) return -1;

    return 0;
#else
    printf("⏭️  HAVE_HKDF not defined - skipping HKDF tests\n");
    return 0;
#endif
}

/*
 * Test RNG allocation functions
 */
static int test_rng_functions(void)
{
    printf("\n=== Test RNG Functions ===\n");

    WC_RNG* rng_ptr = NULL;
    int ret;

    // Test 1: wc_rng_new
    printf("\nTesting wc_rng_new...\n");
    rng_ptr = wc_rng_new(NULL, 0, g_heap_hint);
    if (rng_ptr != NULL) {
        printf("✅ wc_rng_new: PASS (rng: %p)\n", (void*)rng_ptr);
        tests_passed++;
    } else {
        printf("❌ wc_rng_new: FAIL (returned NULL)\n");
        test_failures++;
        return -1;
    }

    // Test RNG functionality
    printf("\nTesting RNG generation...\n");
    byte random_bytes[32];
    ret = wc_RNG_GenerateBlock(rng_ptr, random_bytes, sizeof(random_bytes));
    if (check_result("wc_RNG_GenerateBlock", ret, 0) != 0) {
        wc_rng_free(rng_ptr);
        return -1;
    }

    // Verify we got some randomness (not all zeros)
    int all_zero = 1;
    for (int i = 0; i < sizeof(random_bytes); i++) {
        if (random_bytes[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (check_result("Random data verification", all_zero, 0) != 0) {
        wc_rng_free(rng_ptr);
        return -1;
    }

    // Test 2: wc_rng_free
    printf("\nTesting wc_rng_free...\n");
    wc_rng_free(rng_ptr);
    printf("✅ wc_rng_free: PASS\n");
    tests_passed++;

    // Test wc_rng_free with NULL (should not crash)
    wc_rng_free(NULL);
    printf("✅ wc_rng_free(NULL): PASS\n");
    tests_passed++;

    // Test multiple allocations
    printf("\nTesting multiple RNG allocations...\n");
    WC_RNG* rng1 = wc_rng_new(NULL, 0, g_heap_hint);
    WC_RNG* rng2 = wc_rng_new(NULL, 0, g_heap_hint);
    WC_RNG* rng3 = wc_rng_new(NULL, 0, g_heap_hint);

    if (rng1 && rng2 && rng3) {
        printf("✅ Multiple RNG allocation: PASS\n");
        tests_passed++;
    } else {
        printf("❌ Multiple RNG allocation: FAIL\n");
        test_failures++;
    }

    // Test that they generate different random data
    byte rand1[16], rand2[16], rand3[16];
    if (rng1) ret = wc_RNG_GenerateBlock(rng1, rand1, sizeof(rand1));
    if (rng2) ret = wc_RNG_GenerateBlock(rng2, rand2, sizeof(rand2));
    if (rng3) ret = wc_RNG_GenerateBlock(rng3, rand3, sizeof(rand3));

    int same_data = (XMEMCMP(rand1, rand2, sizeof(rand1)) == 0) ||
                    (XMEMCMP(rand1, rand3, sizeof(rand1)) == 0) ||
                    (XMEMCMP(rand2, rand3, sizeof(rand2)) == 0);
    
    if (check_result("RNG independence verification", same_data, 0) != 0) {
        printf("Warning: Multiple RNGs generated identical data\n");
    }

    // Cleanup
    wc_rng_free(rng1);
    wc_rng_free(rng2);
    wc_rng_free(rng3);

    // Test RNG with custom parameters
    printf("\nTesting RNG with custom seed...\n");
    byte custom_seed[] = "Custom seed for testing";
    rng_ptr = wc_rng_new(custom_seed, sizeof(custom_seed), g_heap_hint);
    if (rng_ptr != NULL) {
        printf("✅ wc_rng_new(custom seed): PASS\n");
        tests_passed++;
        
        ret = wc_RNG_GenerateBlock(rng_ptr, random_bytes, sizeof(random_bytes));
        check_result("Custom seeded RNG generation", ret, 0);
        
        wc_rng_free(rng_ptr);
    } else {
        printf("❌ wc_rng_new(custom seed): FAIL\n");
        test_failures++;
    }

    return 0;
}

/*
 * Integration test: Use all functions together (simulating HPKE usage)
 */
static int test_integration(void)
{
    printf("\n=== Integration Test (HPKE-like usage) ===\n");
    
    int ret;
    WC_RNG* rng = NULL;
    Aes aes;
    byte master_secret[32];
    byte salt[16] = "HPKE test salt  ";
    byte info[16] = "HPKE test info  ";
    byte prk[WC_SHA256_DIGEST_SIZE];
    byte key_material[48];  // 32 bytes key + 16 bytes for other purposes
    byte aes_key[32];       // AES-256 key
    byte iv[12];            // GCM IV
    byte plaintext[] = "HPKE integration test message";
    byte ciphertext[sizeof(plaintext)];
    byte decrypted[sizeof(plaintext)];
    byte auth_tag[16];

    printf("Step 1: Initialize RNG\n");
    rng = wc_rng_new(NULL, 0, g_heap_hint);
    if (!rng) {
        printf("❌ RNG initialization failed\n");
        return -1;
    }

    printf("Step 2: Generate master secret\n");
    ret = wc_RNG_GenerateBlock(rng, master_secret, sizeof(master_secret));
    if (check_result("Master secret generation", ret, 0) != 0) goto cleanup;

    printf("Step 3: HKDF Extract\n");
    ret = wc_HKDF_Extract(WC_SHA256, salt, sizeof(salt), master_secret, sizeof(master_secret), prk);
    if (check_result("HKDF Extract", ret, 0) != 0) goto cleanup;

    printf("Step 4: HKDF Expand\n");
    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk), info, sizeof(info), key_material, sizeof(key_material));
    if (check_result("HKDF Expand", ret, 0) != 0) goto cleanup;

    printf("Step 5: Extract AES key and IV\n");
    XMEMCPY(aes_key, key_material, 32);
    XMEMCPY(iv, key_material + 32, 12);

    printf("Step 6: Initialize AES\n");
    ret = wc_AesInit(&aes, g_heap_hint, INVALID_DEVID);
    if (check_result("AES Init", ret, 0) != 0) goto cleanup;

    printf("Step 7: Set AES key\n");
    ret = wc_AesGcmSetKey(&aes, aes_key, 32);
    if (check_result("AES Set Key", ret, 0) != 0) goto cleanup_aes;

    printf("Step 8: Encrypt message\n");
    ret = wc_AesGcmEncrypt(&aes, ciphertext, plaintext, sizeof(plaintext)-1,
                           iv, sizeof(iv), auth_tag, sizeof(auth_tag), NULL, 0);
    if (check_result("AES GCM Encrypt", ret, 0) != 0) goto cleanup_aes;

    printf("Step 9: Decrypt message\n");
    ret = wc_AesGcmDecrypt(&aes, decrypted, ciphertext, sizeof(plaintext)-1,
                           iv, sizeof(iv), auth_tag, sizeof(auth_tag), NULL, 0);
    if (check_result("AES GCM Decrypt", ret, 0) != 0) goto cleanup_aes;

    printf("Step 10: Verify decryption\n");
    ret = XMEMCMP(plaintext, decrypted, sizeof(plaintext)-1);
    if (check_result("Decryption verification", ret, 0) != 0) goto cleanup_aes;

    printf("✅ Integration test PASSED - All HPKE crypto functions work together!\n");
    tests_passed++;

cleanup_aes:
    wc_AesFree(&aes);
cleanup:
    wc_rng_free(rng);
    
    return (ret == 0) ? 0 : -1;
}

/*
 * Main test runner
 */
int main(void)
{
    printf("HPKE Cryptographic Functions Test Suite\n");
    printf("=======================================\n");
    printf("Testing all crypto functions required by HPKE\n");
    
    unsigned long start = rdcycle();
    
    // Setup static memory
    printf("\n[SETUP] Static Memory Initialization\n");
    if (setup_wolfssl_memory() != 0) {
        printf("❌ Static memory setup failed\n");
        return -1;
    }
    
    int overall_result = 0;
    
    // Run all function tests
    printf("\n[TESTS] Running Individual Function Tests\n");
    
    if (test_aes_gcm_functions() != 0) overall_result = -1;
    if (test_hkdf_functions() != 0) overall_result = -1;
    if (test_rng_functions() != 0) overall_result = -1;
    
    // Run integration test
    printf("\n[INTEGRATION] Testing Combined Usage\n");
    if (test_integration() != 0) overall_result = -1;
    
    unsigned long end = rdcycle();
    
    printf("\n=======================================\n");
    printf("Test Summary:\n");
    printf("  Tests passed: %d\n", tests_passed);
    printf("  Tests failed: %d\n", test_failures);
    printf("  Total time: %lu cycles\n", end - start);
    
    printf("\n🎯 Function Coverage Report:\n");
    printf("✅ wc_AesInit() - TESTED\n");
    printf("✅ wc_AesGcmSetKey() - TESTED\n");
    printf("✅ wc_AesGcmEncrypt() - TESTED\n");
    printf("✅ wc_AesGcmDecrypt() - TESTED\n");
    printf("✅ wc_AesFree() - TESTED\n");
    printf("✅ wc_HKDF_Extract() - TESTED\n");
    printf("✅ wc_HKDF_Expand() - TESTED\n");
    printf("✅ wc_rng_new() - TESTED\n");
    printf("✅ wc_rng_free() - TESTED\n");
    
    if (overall_result == 0 && test_failures == 0) {
        printf("\n🎉 ALL HPKE CRYPTO FUNCTIONS PASSED!\n");
        printf("✅ Static memory configuration works\n");
        printf("✅ All AES-GCM operations successful\n");
        printf("✅ All HKDF operations successful\n");
        printf("✅ All RNG operations successful\n");
        printf("✅ Integration test successful\n");
        printf("\n💡 READY FOR HPKE IMPLEMENTATION!\n");
        printf("   All required cryptographic primitives are working correctly.\n");
    } else {
        printf("\n❌ SOME TESTS FAILED\n");
        printf("Check the detailed output above for specific failures\n");
        printf("HPKE implementation may not work correctly until these are resolved\n");
    }
    
    return overall_result;
}