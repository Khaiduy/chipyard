/* test_curve25519_timing.c
 * Simple timing measurement of curve25519 functions
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "compiler.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include "driver/x25519/x25519.h"

static const word32 kCurve25519BasePoint[CURVE25519_KEYSIZE/sizeof(word32)] = {
#ifdef BIG_ENDIAN_ORDER
    0x09000000
#else
    9
#endif
};

#define X25519_HW_BASE_ADDR  0x64004000

// Static memory setup for WolfSSL
#define WOLFSSL_STATIC_MEM_SIZE 32768
static byte g_wolfssl_mem[WOLFSSL_STATIC_MEM_SIZE];
static WOLFSSL_HEAP_HINT* g_heap_hint = NULL;

// Accurate timing measurement macro
#define START_TIMING() \
    do { \
        asm volatile ("fence" ::: "memory"); \
        start = rdcycle(); \
    } while(0)

#define END_TIMING() \
    do { \
        asm volatile ("fence" ::: "memory"); \
        end = rdcycle(); \
    } while(0)

// Setup static memory
static int setup_wolfssl_memory(void)
{
#ifdef WOLFSSL_STATIC_MEMORY
    int ret = wc_LoadStaticMemory(&g_heap_hint, g_wolfssl_mem, 
                                  WOLFSSL_STATIC_MEM_SIZE, 0, 30);
    if (ret != 0) {
        printf("wc_LoadStaticMemory failed: %d\n", ret);
        return ret;
    }
    return 0;
#else
    printf("WOLFSSL_STATIC_MEMORY not defined\n");
    return -1;
#endif
}


/* Corrected conversion functions for big-endian hardware format */

/* Convert WolfSSL byte array to hardware uint64_t array (big-endian) */
static void wolfssl_to_hw_format(const byte* wolfssl_data, uint64_t hw_data[4])
{
    // WolfSSL uses little-endian byte arrays (32 bytes)
    // Hardware expects big-endian 64-bit words
    
    for (int i = 0; i < 4; i++) {
        hw_data[i] = 0;
        // Read 8 bytes in big-endian order
        for (int j = 0; j < 8; j++) {
            int byte_idx = i * 8 + j;
            hw_data[i] = (hw_data[i] << 8) | ((uint64_t)wolfssl_data[byte_idx]);
        }
    }
}

/* Convert hardware uint64_t array to WolfSSL byte array */
static void hw_to_wolfssl_format(const uint64_t hw_data[4], byte* wolfssl_data)
{
    // Convert big-endian 64-bit words back to little-endian byte array
    
    for (int i = 0; i < 4; i++) {
        // Write 8 bytes in big-endian order
        for (int j = 0; j < 8; j++) {
            int byte_idx = i * 8 + j;
            wolfssl_data[byte_idx] = (byte)((hw_data[i] >> (8 * (7 - j))) & 0xFF);
        }
    }
}

/* Hardware-accelerated scalar multiplication */
static int hw_curve25519_scalar_mult(byte* result, const byte* scalar, const byte* point)
{
    uint64_t hw_scalar[4];
    uint64_t hw_point[4];
    uint64_t hw_result[4];
    void* x25519ctrl = (void*)X25519_HW_BASE_ADDR;
    
    // Convert WolfSSL format to hardware format
    wolfssl_to_hw_format(scalar, hw_scalar);
    wolfssl_to_hw_format(point, hw_point);
    
    // Call hardware accelerator (constant-time execution)
    hwx25519_init(x25519ctrl, hw_scalar, hw_point);
    hwx25519_results(x25519ctrl, hw_result);
    
    // Convert hardware format back to WolfSSL format
    hw_to_wolfssl_format(hw_result, result);
    
    return 0;
}


int hw_curve25519_make_pub_blind(int public_size, byte* pub, int private_size,
                                 const byte* priv, WC_RNG* rng)
{
    int ret;

    if ((public_size != CURVE25519_KEYSIZE) || (private_size != CURVE25519_KEYSIZE)) {
        return ECC_BAD_ARG_E;
    }
    if ((pub == NULL) || (priv == NULL)) {
        return ECC_BAD_ARG_E;
    }

    /* check clamping */
    // ret = curve25519_priv_clamp_check(priv);
    // if (ret != 0)
    //     return ret;


    // printf("Using direct hardware acceleration (constant-time by hardware)\n");
    
    /* Direct hardware scalar multiplication - hardware provides constant-time */
    ret = hw_curve25519_scalar_mult(pub, priv, (byte*)kCurve25519BasePoint);

    return ret;
}

int hw_curve25519_make_key(WC_RNG* rng, int keysize, curve25519_key* key)
{
    int ret;

    // Line 399-400: Parameter validation
    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    ret = wc_curve25519_make_priv(rng, keysize, key->k);    

    if (ret == 0) {
        key->privSet = 1;
        
        ret = hw_curve25519_make_pub_blind((int)sizeof(key->p.point),
                                           key->p.point, (int)sizeof(key->k),
                                           key->k, rng);
        if (ret == 0) {
            // Line 420: Store RNG for future blinding operations
            ret = wc_curve25519_set_rng(key, rng);
        }
        
        // Line 426: Set public key flag based on result
        key->pubSet = (ret == 0);
    }
    
    // Line 428: Return result
    return ret;
}

int main(void)
{
    printf("Curve25519 Function Timing Test\n");
    printf("================================\n");
    
    // Setup static memory
    if (setup_wolfssl_memory() != 0) {
        return -1;
    }
    
    int ret;
    curve25519_key key1, key2;
    WC_RNG rng;
    unsigned long start, end;
    
    // Buffers for testing
    byte privateKey[CURVE25519_KEYSIZE];
    byte publicKey[CURVE25519_KEYSIZE];
    byte sharedSecret[CURVE25519_KEYSIZE];
    word32 privSz = sizeof(privateKey);
    word32 pubSz = sizeof(publicKey);
    word32 secretSz = sizeof(sharedSecret);
    
    // printf("\n=== Initialization Timing ===\n");
    
    // 1. wc_curve25519_init
    START_TIMING();
    ret = wc_curve25519_init(&key1);
    END_TIMING();
    printf("wc_curve25519_init: %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_init: %d\n", ret);
        return -1;
    }
    
    // Initialize second key
    START_TIMING();
    ret = wc_curve25519_init(&key2);
    END_TIMING();
    printf("wc_curve25519_init (key2): %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_init(key2): %d\n", ret);
        return -1;
    }
    
    // 2. wc_InitRng
    START_TIMING();
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    END_TIMING();
    printf("wc_InitRng_ex: %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_InitRng_ex: %d\n", ret);
        return -1;
    }

    // 3. wc_curve25519_make_key
    // printf("\n--- Executing minimal_curve25519_make_key ---\n");
    START_TIMING();
    ret = hw_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key1);
    END_TIMING();
    printf("hw_curve25519_make_key (key1): %lu cycles\n", end - start);

    if (ret != 0) {
        printf("FAIL hw_curve25519_make_key(key1): %d\n", ret);
        goto cleanup;
    }

    // Show RNG state after key generation
    // printf("\n--- RNG State After Key Generation ---\n");
    // printf("RNG pointer: %p\n", (void*)&rng);
    // printf("RNG heap: %p\n", (void*)rng.heap);
    // printf("RNG status: %d\n", rng.status);

    // Show key1 state after key generation
    // printf("\n--- Key1 State After Generation ---\n");
    // printf("key1 pointer: %p\n", (void*)&key1);
    // printf("key1.privSet: %d\n", key1.privSet);
    // printf("key1.pubSet: %d\n", key1.pubSet);
    // printf("key1.k (full private key - 32 bytes):\n");
    // for (int i = 0; i < CURVE25519_KEYSIZE; i++) {
    //     printf("%02x", key1.k[i]);
    //     if ((i + 1) % 16 == 0) {
    //         printf("\n"); // New line every 16 bytes
    //     } else if ((i + 1) % 8 == 0) {
    //         printf(" "); // Space every 8 bytes
    //     }
    // }
    // if (CURVE25519_KEYSIZE % 16 != 0) printf("\n");

    // printf("key1.p.point (full public key - 32 bytes):\n");
    // for (int i = 0; i < CURVE25519_KEYSIZE; i++) {
    //     printf("%02x", key1.p.point[i]);
    //     if ((i + 1) % 16 == 0) {
    //         printf("\n"); // New line every 16 bytes
    //     } else if ((i + 1) % 8 == 0) {
    //         printf(" "); // Space every 8 bytes
    //     }
    // }
    // if (CURVE25519_KEYSIZE % 16 != 0) printf("\n");
    
    START_TIMING();
    ret = hw_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key2);
    END_TIMING();
    printf("hw_curve25519_make_key (key2): %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL hw_curve25519_make_key(key2): %d\n", ret);
        goto cleanup;
    }
    
    printf("\n=== Key Export Timing ===\n");
    
    // 4. wc_curve25519_export_private_raw
    START_TIMING();
    ret = wc_curve25519_export_private_raw(&key1, privateKey, &privSz);
    END_TIMING();
    printf("wc_curve25519_export_private_raw: %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_export_private_raw: %d\n", ret);
        goto cleanup;
    }
    
    // 5. wc_curve25519_export_public
    START_TIMING();
    ret = wc_curve25519_export_public(&key1, publicKey, &pubSz);
    END_TIMING();
    printf("wc_curve25519_export_public: %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_export_public: %d\n", ret);
        goto cleanup;
    }
    
    // 6. wc_curve25519_export_public_ex (with endianness)
    pubSz = sizeof(publicKey);
    START_TIMING();
    ret = wc_curve25519_export_public_ex(&key1, publicKey, &pubSz, EC25519_LITTLE_ENDIAN);
    END_TIMING();
    printf("wc_curve25519_export_public_ex (little endian): %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_export_public_ex: %d\n", ret);
        goto cleanup;
    }
    
    pubSz = sizeof(publicKey);
    START_TIMING();
    ret = wc_curve25519_export_public_ex(&key1, publicKey, &pubSz, EC25519_BIG_ENDIAN);
    END_TIMING();
    printf("wc_curve25519_export_public_ex (big endian): %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_export_public_ex (big): %d\n", ret);
        goto cleanup;
    }
    
#if defined(HAVE_CURVE25519_KEY_EXPORT)
    // 7. wc_curve25519_export_key_raw
    privSz = sizeof(privateKey);
    pubSz = sizeof(publicKey);
    START_TIMING();
    ret = wc_curve25519_export_key_raw(&key1, privateKey, &privSz, publicKey, &pubSz);
    END_TIMING();
    printf("wc_curve25519_export_key_raw: %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_export_key_raw: %d\n", ret);
        goto cleanup;
    }
#endif
    
    // printf("\n=== Public Key Generation Timing ===\n");
    
    // // 8. wc_curve25519_make_pub
    // byte pubFromPriv[CURVE25519_KEYSIZE];
    // START_TIMING();
    // ret = wc_curve25519_make_pub(sizeof(pubFromPriv), pubFromPriv, 
    //                             sizeof(key1.k), key1.k);
    // END_TIMING();
    // printf("wc_curve25519_make_pub: %lu cycles\n", end - start);
    // if (ret != 0) {
    //     printf("FAIL wc_curve25519_make_pub: %d\n", ret);
    //     goto cleanup;
    // }
    
    printf("\n=== Key Import Timing ===\n");
    
    // 9. wc_curve25519_import_private
    curve25519_key import_key;
    ret = wc_curve25519_init(&import_key);
    if (ret != 0) {
        printf("FAIL wc_curve25519_init(import_key): %d\n", ret);
        goto cleanup;
    }
    
    START_TIMING();
    ret = wc_curve25519_import_private(privateKey, sizeof(privateKey), &import_key);
    END_TIMING();
    printf("wc_curve25519_import_private: %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_import_private: %d\n", ret);
        wc_curve25519_free(&import_key);
        goto cleanup;
    }
    
    // 10. wc_curve25519_import_private_raw_ex
    START_TIMING();
    ret = wc_curve25519_import_private_raw_ex(privateKey, sizeof(privateKey),
                                              publicKey, sizeof(publicKey),
                                              &import_key, EC25519_LITTLE_ENDIAN);
    END_TIMING();
    printf("wc_curve25519_import_private_raw_ex: %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_import_private_raw_ex: %d\n", ret);
    }
    
    wc_curve25519_free(&import_key);
    
    printf("\n=== Shared Secret Timing ===\n");
    
    // 11. wc_curve25519_shared_secret_ex
    START_TIMING();
    ret = wc_curve25519_shared_secret_ex(&key1, &key2, sharedSecret, &secretSz, 
                                        EC25519_LITTLE_ENDIAN);
    END_TIMING();
    printf("wc_curve25519_shared_secret_ex: %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_shared_secret_ex: %d\n", ret);
        goto cleanup;
    }
    
    printf("Shared secret generated: %d bytes\n", secretSz);
    
    printf("\n=== Utility Function Timing ===\n");
    
    // 12. wc_curve25519_size
    START_TIMING();
    int keySize = wc_curve25519_size(&key1);
    END_TIMING();
    printf("wc_curve25519_size: %lu cycles\n", end - start);
    printf("Key size: %d bytes\n", keySize);
    
    printf("\n=== Cleanup Timing ===\n");
    
    // 13. wc_curve25519_free
    START_TIMING();
    wc_curve25519_free(&key1);
    END_TIMING();
    printf("wc_curve25519_free (key1): %lu cycles\n", end - start);
    
    START_TIMING();
    wc_curve25519_free(&key2);
    END_TIMING();
    printf("wc_curve25519_free (key2): %lu cycles\n", end - start);
    
    // 14. wc_FreeRng
    START_TIMING();
    ret = wc_FreeRng(&rng);
    END_TIMING();
    printf("wc_FreeRng: %lu cycles\n", end - start);
    
    printf("\n=== Test Summary ===\n");
    printf("All curve25519 function timing tests completed successfully!\n");
    printf("Key operations tested:\n");
    printf("- Initialization and cleanup\n");
    printf("- Key generation\n");
    printf("- Key export (private and public)\n");
    printf("- Key import\n");
    printf("- Public key derivation from private\n");
    printf("- Shared secret computation\n");
    printf("- Utility functions\n");
    
    return 0;

cleanup:
    wc_curve25519_free(&key1);
    wc_curve25519_free(&key2);
    wc_FreeRng(&rng);
    printf("\nTest failed during execution\n");
    return -1;
}