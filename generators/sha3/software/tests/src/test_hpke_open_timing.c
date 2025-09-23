/* test_hpke_open_timing.c
 * Simple timing measurement of each function in wc_HpkeOpenBase and wc_HpkeSerializePublicKey
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "compiler.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hpke.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/curve25519.h>

// Static memory setup for WolfSSL
#define WOLFSSL_STATIC_MEM_SIZE 65536
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


int main(void)
{
    printf("HPKE Complete Function Timing Test\n");
    printf("===================================\n");
    
    // Setup static memory
    if (setup_wolfssl_memory() != 0) {
        return -1;
    }
    int ret;
    Hpke hpke;
    WC_RNG rng;
    void* ephemeralKey = NULL;
    void* receiverKey = NULL;
    HpkeBaseContext context;
    unsigned long start, end;
    
    // Test data
    const char* info_text = "test info";
    const char* aad_text = "test aad";
    const char* plaintext_text = "Hello HPKE!";
    byte ciphertext[64];
    byte decrypted[64];
    byte pubKey[HPKE_Npk_MAX];
    word16 pubKeySz = sizeof(pubKey);
    
    // Initialize HPKE
    ret = wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, 
                      HPKE_AES_256_GCM, g_heap_hint);
    if (ret != 0) {
        printf("FAIL wc_HpkeInit: %d\n", ret);
        return -1;
    }
    
    // Initialize RNG
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    if (ret != 0) {
        printf("FAIL wc_InitRng_ex: %d\n", ret);
        return -1;
    }
    
    // Generate keys
    ret = hw_HpkeGenerateKeyPair(&hpke, &ephemeralKey, &rng);
    if (ret != 0) {
        printf("FAIL hw_HpkeGenerateKeyPair(ephemeral): %d\n", ret);
        return -1;
    }
    
    ret = hw_HpkeGenerateKeyPair(&hpke, &receiverKey, &rng);
    if (ret != 0) {
        printf("FAIL hw_HpkeGenerateKeyPair(receiver): %d\n", ret);
        return -1;
    }
    
    printf("\n=== HPKE Seal Function Timing ===\n");
    
    // 1. Context allocation
#ifdef WOLFSSL_SMALL_STACK
    START_TIMING();
    HpkeBaseContext* context_ptr = (HpkeBaseContext*)XMALLOC(sizeof(HpkeBaseContext), 
                                                             hpke.heap, DYNAMIC_TYPE_TMP_BUFFER);
    END_TIMING();
    printf("Seal context allocation (XMALLOC): %lu cycles\n", end - start);
    
    if (context_ptr == NULL) {
        printf("FAIL Context allocation failed\n");
        return -1;
    }
    memcpy(&context, context_ptr, sizeof(HpkeBaseContext));
    XFREE(context_ptr, hpke.heap, DYNAMIC_TYPE_TMP_BUFFER);
#else
    START_TIMING();
    // Stack allocation is essentially free
    END_TIMING();
    printf("Seal context allocation (stack): %lu cycles\n", end - start);
#endif
    
    // // 2. wc_HpkeSetupBaseSender
    // START_TIMING();
    // ret = wc_HpkeSetupBaseSender(&hpke, &context, ephemeralKey, receiverKey, 
    //                              (byte*)info_text, (word32)strlen(info_text));
    // END_TIMING();
    // printf("wc_HpkeSetupBaseSender: %lu cycles\n", end - start);
    
    // if (ret != 0) {
    //     printf("FAIL wc_HpkeSetupBaseSender: %d\n", ret);
    //     goto cleanup;
    // }
    
    // // 3. wc_HpkeContextSealBase
    // START_TIMING();
    // ret = wc_HpkeContextSealBase(&hpke, &context, 
    //                              (byte*)aad_text, (word32)strlen(aad_text),
    //                              (byte*)plaintext_text, (word32)strlen(plaintext_text),
    //                              ciphertext);
    // END_TIMING();
    // printf("wc_HpkeContextSealBase: %lu cycles\n", end - start);
    
    // if (ret != 0) {
    //     printf("FAIL wc_HpkeContextSealBase: %d\n", ret);
    //     goto cleanup;
    // }
    
    // printf("\n=== wc_HpkeSerializePublicKey Function Timing ===\n");
    
    // // For X25519, this calls wc_curve25519_export_public_ex
    // START_TIMING();
    // ret = wc_HpkeSerializePublicKey(&hpke, ephemeralKey, pubKey, &pubKeySz);
    // END_TIMING();
    // printf("wc_HpkeSerializePublicKey (X25519): %lu cycles\n", end - start);
    
    // if (ret != 0) {
    //     printf("FAIL wc_HpkeSerializePublicKey: %d\n", ret);
    //     goto cleanup;
    // }
    
    // printf("Public key serialized: %d bytes\n", pubKeySz);
    
    // printf("\n=== wc_HpkeOpenBase Function Timing ===\n");
    
    // Simulate the wc_HpkeOpenBase function step by step
    
    // 1. Context allocation for open
// #ifdef WOLFSSL_SMALL_STACK
//     START_TIMING();
//     HpkeBaseContext* open_context_ptr = (HpkeBaseContext*)XMALLOC(sizeof(HpkeBaseContext), 
//                                                                   hpke.heap, DYNAMIC_TYPE_TMP_BUFFER);
//     END_TIMING();
//     printf("Open context allocation (XMALLOC): %lu cycles\n", end - start);
    
//     if (open_context_ptr == NULL) {
//         printf("FAIL Open context allocation failed\n");
//         goto cleanup;
//     }
    
//     HpkeBaseContext open_context;
//     memcpy(&open_context, open_context_ptr, sizeof(HpkeBaseContext));
//     XFREE(open_context_ptr, hpke.heap, DYNAMIC_TYPE_TMP_BUFFER);
// #else
//     START_TIMING();
//     HpkeBaseContext open_context;
//     END_TIMING();
//     printf("Open context allocation (stack): %lu cycles\n", end - start);
// #endif
    
//     // 2. wc_HpkeSetupBaseReceiver
//     START_TIMING();
//     ret = wc_HpkeSetupBaseReceiver(&hpke, &open_context, receiverKey, pubKey, pubKeySz,
//                                    (byte*)info_text, (word32)strlen(info_text));
//     END_TIMING();
//     printf("wc_HpkeSetupBaseReceiver: %lu cycles\n", end - start);
    
//     if (ret != 0) {
//         printf("FAIL wc_HpkeSetupBaseReceiver: %d\n", ret);
//         goto cleanup;
//     }
    
//     // 3. wc_HpkeContextOpenBase
//     START_TIMING();
//     ret = wc_HpkeContextOpenBase(&hpke, &open_context,
//                                  (byte*)aad_text, (word32)strlen(aad_text),
//                                  ciphertext, (word32)strlen(plaintext_text),
//                                  decrypted);
//     END_TIMING();
//     printf("wc_HpkeContextOpenBase: %lu cycles\n", end - start);
    
//     if (ret != 0) {
//         printf("FAIL wc_HpkeContextOpenBase: %d\n", ret);
//         goto cleanup;
//     }
    
//     // 4. Context cleanup for open
//     START_TIMING();
//     // Context cleanup would happen here in WOLFSSL_SMALL_STACK
//     END_TIMING();
//     printf("Open context cleanup: %lu cycles\n", end - start);
    
//     // Verify decryption worked
//     if (memcmp(decrypted, plaintext_text, strlen(plaintext_text)) == 0) {
//         printf("SUCCESS: Decryption verified!\n");
//         printf("Original:  '%s'\n", plaintext_text);
//         printf("Decrypted: '");
//         for (int i = 0; i < (int)strlen(plaintext_text); i++) {
//             printf("%c", decrypted[i]);
//         }
//         printf("'\n");
//     } else {
//         printf("FAIL: Decryption verification failed\n");
//     }
    
//     printf("\n=== wc_HpkeSerializePublicKey Components (X25519) ===\n");
    
//     // Break down wc_HpkeSerializePublicKey for X25519
//     word32 tmpOutSz = sizeof(pubKey);
    
//     // Argument validation timing (simulated - this check doesn't actually execute)
//     START_TIMING();
//     // Just measure the timing overhead of the check itself
//     END_TIMING();
//     printf("Argument validation: %lu cycles\n", end - start);
    
//     // Size setup
//     START_TIMING();
//     tmpOutSz = pubKeySz;
//     END_TIMING();
//     printf("Size setup: %lu cycles\n", end - start);
    
//     // The actual export function for X25519
//     START_TIMING();
//     ret = wc_curve25519_export_public_ex((curve25519_key*)ephemeralKey, pubKey,
//                                          &tmpOutSz, EC25519_LITTLE_ENDIAN);
//     END_TIMING();
//     printf("wc_curve25519_export_public_ex: %lu cycles\n", end - start);
    
//     // Size assignment
//     START_TIMING();
//     pubKeySz = (word16)tmpOutSz;
//     END_TIMING();
//     printf("Size assignment: %lu cycles\n", end - start);

cleanup:
    // Cleanup
    if (ephemeralKey != NULL) {
        wc_HpkeFreeKey(&hpke, hpke.kem, ephemeralKey, hpke.heap);
    }
    if (receiverKey != NULL) {
        wc_HpkeFreeKey(&hpke, hpke.kem, receiverKey, hpke.heap);
    }
    wc_FreeRng(&rng);
    
    printf("\nAll timing tests completed!\n");
    return 0;
}