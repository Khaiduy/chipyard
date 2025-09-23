/* test_curve25519_component_timing.c - With accurate timing */

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

int main(void)
{
    printf("Curve25519 Function Timing Test (Accurate)\n");
    printf("===========================================\n");
    
    // Setup static memory
    if (setup_wolfssl_memory() != 0) {
        return -1;
    }
    
    int ret;
    WC_RNG rng;
    curve25519_key key;
    unsigned long start, end;
    
    // Initialize RNG
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    if (ret != 0) {
        printf("FAIL wc_InitRng_ex: %d\n", ret);
        return -1;
    }
    
    // Initialize key
    ret = wc_curve25519_init_ex(&key, g_heap_hint, INVALID_DEVID);
    if (ret != 0) {
        printf("FAIL wc_curve25519_init_ex: %d\n", ret);
        return -1;
    }
    
    printf("\nFunction timing measurements (with memory fences):\n");
    
    // 1. wc_curve25519_make_priv
    START_TIMING();
    ret = wc_curve25519_make_priv(&rng, CURVE25519_KEYSIZE, key.k);
    END_TIMING();
    printf("wc_curve25519_make_priv: %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_make_priv: %d\n", ret);
        return -1;
    }
    
    // 2. Set privSet flag
    START_TIMING();
    key.privSet = 1;
    END_TIMING();
    printf("key.privSet = 1: %lu cycles\n", end - start);
    
    // 3. wc_curve25519_make_pub
    START_TIMING();
#ifdef WOLFSSL_CURVE25519_BLINDING
    ret = wc_curve25519_make_pub_blind((int)sizeof(key.p.point),
                                       key.p.point, (int)sizeof(key.k),
                                       key.k, &rng);
    if (ret == 0) {
        ret = wc_curve25519_set_rng(&key, &rng);
    }
#else
    ret = wc_curve25519_make_pub((int)sizeof(key.p.point), key.p.point,
                                 (int)sizeof(key.k), key.k);
#endif
    END_TIMING();
    printf("wc_curve25519_make_pub: %lu cycles\n", end - start);
    if (ret != 0) {
        printf("FAIL wc_curve25519_make_pub: %d\n", ret);
        return -1;
    }
    
    // 4. Set pubSet flag
    START_TIMING();
    key.pubSet = (ret == 0);
    END_TIMING();
    printf("key.pubSet = (ret == 0): %lu cycles\n", end - start);
    
    // Cleanup
    wc_curve25519_free(&key);
    wc_FreeRng(&rng);
    
    printf("\nTest completed successfully!\n");
    return 0;
}