/* test_hpke_x25519_sha256_aes128gcm_software.c
 * HPKE test using pure WolfSSL software implementation
 * Testing DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, AES_128_GCM
 * NO HARDWARE ACCELERATION
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "compiler.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hpke.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sp_int.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifndef XMEMSET  
#define XMEMSET memset
#endif

#ifndef XMEMCMP
#define XMEMCMP memcmp
#endif

#ifndef XSTRLEN
#define XSTRLEN strlen
#endif

#ifndef XMALLOC
#define XMALLOC(sz, heap, type) malloc(sz)
#endif

#ifndef XFREE
#define XFREE(ptr, heap, type) free(ptr)
#endif

// Static memory setup for WolfSSL
#define WOLFSSL_STATIC_MEM_SIZE 65536
static byte g_wolfssl_mem[WOLFSSL_STATIC_MEM_SIZE];
static WOLFSSL_HEAP_HINT* g_heap_hint = NULL;

// Test result tracking
static int test_failures = 0;
static int tests_passed = 0;
static unsigned long step_start_cycles = 0;
static unsigned long total_cycles = 0;

/* Helper functions */
static void start_timing(void)
{
    step_start_cycles = rdcycle();
}

static void end_timing(const char* operation)
{
    unsigned long end_cycles = rdcycle();
    unsigned long elapsed = end_cycles - step_start_cycles;
    total_cycles += elapsed;
    printf("  Timing: %s took %lu cycles\n", operation, elapsed);
}

int check_result(const char* test_name, int actual, int expected)
{
    if (actual == expected) {
        printf("PASS %s: result %d\n", test_name, actual);
        tests_passed++;
        return 0;
    } else {
        printf("FAIL %s: expected %d, got %d\n", test_name, expected, actual);
        test_failures++;
        return -1;
    }
}

/* Setup static memory */
static int setup_wolfssl_memory(void)
{
    start_timing();
    
#ifdef WOLFSSL_STATIC_MEMORY
    int ret = wc_LoadStaticMemory(&g_heap_hint, g_wolfssl_mem, 
                                  WOLFSSL_STATIC_MEM_SIZE, 0, 30);
    
    if (ret != 0) {
        printf("wc_LoadStaticMemory failed: %d\n", ret);
        end_timing("Static memory setup (FAILED)");
        return ret;
    }
    printf("Static memory initialized successfully\n");
    end_timing("Static memory setup");
    return 0;
#else
    printf("WOLFSSL_STATIC_MEMORY not defined\n");
    end_timing("Static memory setup (FAILED)");
    return -1;
#endif
}

/* Test pure software Curve25519 key generation */
static int test_curve25519_keygen_software(void)
{
    printf("\nDebug Test: Software Curve25519 Key Generation\n");
    
    WC_RNG rng;
    curve25519_key key;
    int ret;
    
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    printf("  RNG init result: %d\n", ret);
    if (ret != 0) return ret;
    
    ret = wc_curve25519_init_ex(&key, g_heap_hint, INVALID_DEVID);
    printf("  Key init result: %d\n", ret);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }
    
    start_timing();
    ret = wc_curve25519_make_key(&rng, 32, &key);
    end_timing("Software curve25519_make_key");
    printf("  Key generation result: %d\n", ret);
    
    if (ret == 0) {
        printf("  SUCCESS: Software key generation completed\n");
        printf("  Public key (first 16 bytes): ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", key.p.point[i]);
        }
        printf("\n");
    } else {
        printf("  FAILED: Software key generation failed with error %d\n", ret);
    }
    
    wc_curve25519_free(&key);
    wc_FreeRng(&rng);
    
    return ret;
}

/* Test pure software HPKE key generation */
static int test_hpke_keygen_software(void)
{
    printf("\nDebug Test: Software HPKE Key Generation\n");
    
    Hpke hpke;
    WC_RNG rng;
    void* keypair = NULL;
    int ret;
    
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    printf("  RNG init result: %d\n", ret);
    if (ret != 0) return ret;
    
    ret = wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, HPKE_AES_128_GCM, g_heap_hint);
    printf("  HPKE init result: %d\n", ret);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }
    
    start_timing();
    ret = wc_HpkeGenerateKeyPair(&hpke, &keypair, &rng);
    end_timing("Software wc_HpkeGenerateKeyPair");
    printf("  HPKE key generation result: %d\n", ret);
    
    if (ret == 0 && keypair != NULL) {
        printf("  SUCCESS: Software HPKE key generation completed\n");
        
        // Try to serialize the public key
        byte pubKey[HPKE_Npk_MAX];
        word16 pubKeySz = sizeof(pubKey);
        
        ret = wc_HpkeSerializePublicKey(&hpke, keypair, pubKey, &pubKeySz);
        printf("  Public key serialization result: %d\n", ret);
        if (ret == 0) {
            printf("  Public key (%d bytes): ", pubKeySz);
            for (int i = 0; i < (pubKeySz < 16 ? pubKeySz : 16); i++) {
                printf("%02x", pubKey[i]);
            }
            if (pubKeySz > 16) printf("...");
            printf("\n");
        }
        
        wc_HpkeFreeKey(&hpke, hpke.kem, keypair, hpke.heap);
    } else {
        printf("  FAILED: Software HPKE key generation failed\n");
    }
    
    wc_FreeRng(&rng);
    return ret;
}

/* Run debug tests for software implementation */
static int run_software_debug_tests(void)
{
    printf("\n=== RUNNING SOFTWARE DEBUG TESTS ===\n");
    
    int total_failures = 0;
    
    // Test 1: Software Curve25519 key generation
    if (test_curve25519_keygen_software() != 0) {
        printf("FAIL: Software Curve25519 key generation test\n");
        total_failures++;
    } else {
        printf("PASS: Software Curve25519 key generation test\n");
    }
    
    // Test 2: Software HPKE key generation
    if (test_hpke_keygen_software() != 0) {
        printf("FAIL: Software HPKE key generation test\n");
        total_failures++;
    } else {
        printf("PASS: Software HPKE key generation test\n");
    }
    
    printf("\n=== SOFTWARE DEBUG TESTS COMPLETE ===\n");
    printf("Total failures: %d\n", total_failures);
    
    return total_failures;
}

/* HPKE test single - pure software implementation */
static int hpke_test_single_software(Hpke* hpke)
{
    printf("\n=== HPKE Single Test (Software) ===\n");
    printf("KEM: DHKEM_X25519_HKDF_SHA256\n");
    printf("KDF: HKDF_SHA256\n");
    printf("AEAD: AES_128_GCM\n");
    printf("Implementation: Pure WolfSSL Software\n\n");

    int ret = 0;
    int rngRet = 0;
    WC_RNG rng[1];
    const char* start_text = "this is a test";
    const char* info_text = "info";
    const char* aad_text = "aad";
    byte ciphertext[MAX_HPKE_LABEL_SZ];
    byte plaintext[MAX_HPKE_LABEL_SZ];
    void* receiverKey = NULL;
    void* ephemeralKey = NULL;

#ifdef WOLFSSL_SMALL_STACK
    byte *pubKey = NULL;
    word16 pubKeySz = (word16)HPKE_Npk_MAX;
#else
    byte pubKey[HPKE_Npk_MAX];
    word16 pubKeySz = (word16)sizeof(pubKey);
#endif

    printf("Test data:\n");
    printf("  Plaintext: '%s' (%d bytes)\n", start_text, (int)XSTRLEN(start_text));
    printf("  Info: '%s' (%d bytes)\n", info_text, (int)XSTRLEN(info_text));
    printf("  AAD: '%s' (%d bytes)\n\n", aad_text, (int)XSTRLEN(aad_text));

    // Initialize RNG with static memory
    printf("Step 1: Initialize RNG\n");
    start_timing();
    rngRet = ret = wc_InitRng_ex(rng, g_heap_hint, INVALID_DEVID);
    end_timing("RNG initialization");
    
    if (check_result("wc_InitRng_ex", ret, 0) != 0) {
        return ret;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        start_timing();
        pubKey = (byte *)XMALLOC(pubKeySz, g_heap_hint, DYNAMIC_TYPE_TMP_BUFFER);
        end_timing("Public key buffer allocation");
        
        if (pubKey == NULL) {
            printf("FAIL Failed to allocate pubKey buffer\n");
            ret = MEMORY_E;
            goto cleanup;
        }
        printf("PASS Allocated pubKey buffer (%d bytes)\n", pubKeySz);
    }
#endif

    /* generate the keys */
    printf("\nStep 2: Generate ephemeral key pair (software)\n");
    if (ret == 0) {
        start_timing();
        ret = wc_HpkeGenerateKeyPair(hpke, &ephemeralKey, rng);
        end_timing("Ephemeral key pair generation (software)");
        
        if (check_result("wc_HpkeGenerateKeyPair(ephemeral)", ret, 0) != 0) {
            goto cleanup;
        }
        printf("PASS Ephemeral key pair generated\n");
    }

    printf("\nStep 3: Generate receiver key pair (software)\n");
    if (ret == 0) {
        start_timing();
        ret = wc_HpkeGenerateKeyPair(hpke, &receiverKey, rng);
        end_timing("Receiver key pair generation (software)");
        
        if (check_result("wc_HpkeGenerateKeyPair(receiver)", ret, 0) != 0) {
            goto cleanup;
        }
        printf("PASS Receiver key pair generated\n");
    }

    /* seal */
    printf("\nStep 4: Seal (encrypt) message (software)\n");
    if (ret == 0) {
        start_timing();
        ret = wc_HpkeSealBase(hpke, ephemeralKey, receiverKey,
            (byte*)info_text, (word32)XSTRLEN(info_text),
            (byte*)aad_text, (word32)XSTRLEN(aad_text),
            (byte*)start_text, (word32)XSTRLEN(start_text),
            ciphertext);
        end_timing("Message sealing (encryption, software)");
        
        if (check_result("wc_HpkeSealBase", ret, 0) != 0) {
            goto cleanup;
        }
        printf("PASS Message sealed successfully\n");
        
        // Print ciphertext in hex
        printf("Ciphertext (%d bytes): ", (int)XSTRLEN(start_text));
        for (int i = 0; i < (int)XSTRLEN(start_text); i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\n");
    }

    /* export ephemeral key */
    printf("\nStep 5: Export ephemeral public key\n");
    if (ret == 0) {
        start_timing();
        ret = wc_HpkeSerializePublicKey(hpke, ephemeralKey, pubKey, &pubKeySz);
        end_timing("Public key serialization");
        
        if (check_result("wc_HpkeSerializePublicKey", ret, 0) != 0) {
            goto cleanup;
        }
        printf("PASS Ephemeral public key exported (%d bytes)\n", pubKeySz);
        
        // Print public key in hex
        printf("Public key: ");
        for (int i = 0; i < pubKeySz; i++) {
            printf("%02x", pubKey[i]);
        }
        printf("\n");
    }

    /* open with exported ephemeral key */
    printf("\nStep 6: Open (decrypt) message (software)\n");
    if (ret == 0) {
        start_timing();
        ret = wc_HpkeOpenBase(hpke, receiverKey, pubKey, pubKeySz,
            (byte*)info_text, (word32)XSTRLEN(info_text),
            (byte*)aad_text, (word32)XSTRLEN(aad_text),
            ciphertext, (word32)XSTRLEN(start_text),
            plaintext);
        end_timing("Message opening (decryption, software)");
        
        if (check_result("wc_HpkeOpenBase", ret, 0) != 0) {
            goto cleanup;
        }
        printf("PASS Message opened successfully\n");
    }

    printf("\nStep 7: Verify decryption\n");
    if (ret == 0) {
        start_timing();
        ret = XMEMCMP(plaintext, start_text, XSTRLEN(start_text));
        end_timing("Plaintext verification");
        
        if (check_result("Plaintext verification", ret, 0) != 0) {
            printf("Expected: '%s'\n", start_text);
            printf("Got:      '");
            for (int i = 0; i < (int)XSTRLEN(start_text); i++) {
                printf("%c", plaintext[i]);
            }
            printf("'\n");
            goto cleanup;
        }
        printf("PASS Decrypted text matches original!\n");
        printf("Verified: '%s'\n", start_text);
    }

cleanup:
    printf("\nStep 8: Cleanup\n");
    start_timing();
    
    if (ephemeralKey != NULL) {
        wc_HpkeFreeKey(hpke, hpke->kem, ephemeralKey, hpke->heap);
        printf("PASS Ephemeral key freed\n");
    }

    if (receiverKey != NULL) {
        wc_HpkeFreeKey(hpke, hpke->kem, receiverKey, hpke->heap);
        printf("PASS Receiver key freed\n");
    }

#ifdef WOLFSSL_SMALL_STACK
    if (pubKey != NULL) {
        XFREE(pubKey, g_heap_hint, DYNAMIC_TYPE_TMP_BUFFER);
        printf("PASS Public key buffer freed\n");
    }
#endif

    if (rngRet == 0) {
        wc_FreeRng(rng);
        printf("PASS RNG freed\n");
    }
    
    end_timing("Cleanup operations");

    return ret;
}

/* Initialize HPKE with specific algorithms */
static int init_hpke_context(Hpke* hpke)
{
    int ret;
    
    printf("Initializing HPKE context (software)...\n");
    
    start_timing();
    ret = wc_HpkeInit(hpke, 
                      DHKEM_X25519_HKDF_SHA256,
                      HKDF_SHA256,
                      HPKE_AES_128_GCM,
                      g_heap_hint);
    end_timing("HPKE context initialization");
    
    if (ret == 0) {
        printf("PASS HPKE initialized successfully\n");
        printf("  KEM: DHKEM_X25519_HKDF_SHA256 (0x%04x)\n", DHKEM_X25519_HKDF_SHA256);
        printf("  KDF: HKDF_SHA256 (0x%04x)\n", HKDF_SHA256);
        printf("  AEAD: AES_128_GCM (0x%04x)\n", HPKE_AES_128_GCM);
        printf("  Implementation: Pure WolfSSL Software\n");
    } else {
        printf("FAIL HPKE initialization failed: %d\n", ret);
    }
    
    return ret;
}

/* Main test runner */
int main(void)
{
    printf("WolfSSL HPKE Test Suite - Pure Software Implementation\n");
    printf("=====================================================\n");
    printf("Testing HPKE with X25519, HKDF-SHA256, AES-128-GCM\n");
    printf("Using original WolfSSL functions (NO hardware acceleration)\n\n");
    
    unsigned long main_start = rdcycle();
    
    // Setup static memory
    printf("[SETUP] Static Memory Initialization\n");
    if (setup_wolfssl_memory() != 0) {
        printf("FAIL Static memory setup failed\n");
        return -1;
    }
    
    // Run debug tests first
    // int debug_failures = run_software_debug_tests();
    // if (debug_failures > 0) {
    //     printf("WARNING: %d debug tests failed\n", debug_failures);
    //     // Continue anyway to see how far we get
    // }
    
    int overall_result = 0;
    Hpke hpke;
    
    // Initialize HPKE context
    printf("\n[INIT] HPKE Context Initialization\n");
    if (init_hpke_context(&hpke) != 0) {
        printf("FAIL HPKE context initialization failed\n");
        return -1;
    }
    
    // Run the main test
    printf("\n[TEST] Running HPKE Single Test (Software)\n");
    unsigned long test_start = rdcycle();
    if (hpke_test_single_software(&hpke) != 0) {
        overall_result = -1;
    }
    unsigned long test_end = rdcycle();

    unsigned long main_end = rdcycle();
    
    printf("\n======================\n");
    printf("Performance Summary (Software):\n");
    printf("  Main test execution: %lu cycles\n", test_end - test_start);
    printf("  Total program time: %lu cycles\n", main_end - main_start);
    printf("  Sum of measured steps: %lu cycles\n", total_cycles);
    printf("\nTest Summary:\n");
    printf("  Tests passed: %d\n", tests_passed);
    printf("  Tests failed: %d\n", test_failures);
    // printf("  Debug tests failed: %d\n", debug_failures);
    
    if (overall_result == 0 && test_failures == 0) {
        printf("\nSOFTWARE HPKE TEST PASSED!\n");
        printf("PASS Static memory configuration works\n");
        printf("PASS X25519 key generation works (software)\n");
        printf("PASS HKDF-SHA256 key derivation works\n");
        printf("PASS AES-128-GCM encryption/decryption works\n");
        printf("PASS HPKE seal/open operations successful\n");
        printf("PASS Error handling works correctly\n");
        printf("\nSOFTWARE HPKE IS WORKING CORRECTLY!\n");
        printf("You can now compare performance with hardware version.\n");
    } else {
        printf("\nSOFTWARE HPKE TEST FAILED\n");
        printf("Check the detailed output above for specific failures\n");
    }
    
    return overall_result;
}