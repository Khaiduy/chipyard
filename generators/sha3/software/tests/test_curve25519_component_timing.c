/* test_curve25519_component_timing.c
 * Measure execution time of each component in wc_curve25519_make_key
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

// Static memory setup for WolfSSL
#define WOLFSSL_STATIC_MEM_SIZE 32768
static byte g_wolfssl_mem[WOLFSSL_STATIC_MEM_SIZE];
static WOLFSSL_HEAP_HINT* g_heap_hint = NULL;

// Component timing structure
typedef struct {
    unsigned long min_cycles;
    unsigned long max_cycles;
    unsigned long total_cycles;
    unsigned long count;
    double avg_cycles;
} ComponentTiming;

// All timing components
typedef struct {
    ComponentTiming make_priv;     // wc_curve25519_make_priv
    ComponentTiming set_priv_flag; // key->privSet = 1
    ComponentTiming make_pub;      // wc_curve25519_make_pub
    ComponentTiming set_pub_flag;  // key->pubSet = (ret == 0)
    ComponentTiming total;         // Total wc_curve25519_make_key
} AllTimings;

// Helper function to update timing statistics
static void update_timing(ComponentTiming* timing, unsigned long cycles)
{
    if (timing->count == 0) {
        timing->min_cycles = cycles;
        timing->max_cycles = cycles;
        timing->total_cycles = cycles;
    } else {
        if (cycles < timing->min_cycles) timing->min_cycles = cycles;
        if (cycles > timing->max_cycles) timing->max_cycles = cycles;
        timing->total_cycles += cycles;
    }
    timing->count++;
    timing->avg_cycles = (double)timing->total_cycles / timing->count;
}

// Print timing statistics
static void print_component_timing(const char* name, ComponentTiming* timing)
{
    printf("  %s:\n", name);
    printf("    Iterations: %lu\n", timing->count);
    printf("    Min cycles: %lu\n", timing->min_cycles);
    printf("    Max cycles: %lu\n", timing->max_cycles);
    printf("    Avg cycles: %.2f\n", timing->avg_cycles);
    printf("    Total cycles: %lu\n", timing->total_cycles);
    if (timing->count > 1) {
        printf("    Variation: %lu cycles (%.2f%%)\n", 
               timing->max_cycles - timing->min_cycles,
               ((double)(timing->max_cycles - timing->min_cycles) / timing->avg_cycles) * 100.0);
    }
    printf("\n");
}

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
    printf("Static memory initialized successfully\n");
    return 0;
#else
    printf("WOLFSSL_STATIC_MEMORY not defined\n");
    return -1;
#endif
}

/*
 * Manual implementation of wc_curve25519_make_key with detailed timing
 * Based on the actual wolfssl/wolfcrypt/src/curve25519.c implementation
 */
static int curve25519_make_key_with_timing(WC_RNG* rng, int keysize, 
                                          curve25519_key* key, AllTimings* timings)
{
    int ret;
    unsigned long start_cycles, end_cycles;
    unsigned long total_start = rdcycle();

    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }

    printf("  Step-by-step timing breakdown:\n");

    // Step 1: Generate private key - wc_curve25519_make_priv
    printf("    1. Generating private key...\n");
    start_cycles = rdcycle();
    ret = wc_curve25519_make_priv(rng, keysize, key->k);
    end_cycles = rdcycle();
    update_timing(&timings->make_priv, end_cycles - start_cycles);
    printf("       wc_curve25519_make_priv: %lu cycles\n", end_cycles - start_cycles);
    
    if (ret != 0) {
        printf("       FAIL wc_curve25519_make_priv: %d\n", ret);
        return ret;
    }

    // Step 2: Set private key flag
    printf("    2. Setting private key flag...\n");
    start_cycles = rdcycle();
    key->privSet = 1;
    end_cycles = rdcycle();
    update_timing(&timings->set_priv_flag, end_cycles - start_cycles);
    printf("       key->privSet = 1: %lu cycles\n", end_cycles - start_cycles);

    // Step 3: Generate public key from private key
    printf("    3. Generating public key from private...\n");
    start_cycles = rdcycle();
#ifdef WOLFSSL_CURVE25519_BLINDING
    ret = wc_curve25519_make_pub_blind((int)sizeof(key->p.point),
                                       key->p.point, (int)sizeof(key->k),
                                       key->k, rng);
    if (ret == 0) {
        ret = wc_curve25519_set_rng(key, rng);
    }
#else
    ret = wc_curve25519_make_pub((int)sizeof(key->p.point), key->p.point,
                                 (int)sizeof(key->k), key->k);
#endif
    end_cycles = rdcycle();
    update_timing(&timings->make_pub, end_cycles - start_cycles);
    printf("       wc_curve25519_make_pub: %lu cycles\n", end_cycles - start_cycles);

    if (ret != 0) {
        printf("       FAIL wc_curve25519_make_pub: %d\n", ret);
        return ret;
    }

    // Step 4: Set public key flag
    printf("    4. Setting public key flag...\n");
    start_cycles = rdcycle();
    key->pubSet = (ret == 0);
    end_cycles = rdcycle();
    update_timing(&timings->set_pub_flag, end_cycles - start_cycles);
    printf("       key->pubSet = (ret == 0): %lu cycles\n", end_cycles - start_cycles);

    unsigned long total_end = rdcycle();
    update_timing(&timings->total, total_end - total_start);
    printf("    Total manual timing: %lu cycles\n", total_end - total_start);

    return ret;
}

/*
 * Test component timing of wc_curve25519_make_key
 */
static int test_curve25519_component_timing(int iterations)
{
    int ret = 0;
    WC_RNG rng;
    AllTimings timings = {0};
    
    printf("\n=== Curve25519 Component Timing Analysis ===\n");
    printf("Breaking down wc_curve25519_make_key into individual components\n");
    printf("Testing %d iterations\n\n", iterations);
    
    // Initialize RNG
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    if (ret != 0) {
        printf("FAIL wc_InitRng_ex: %d\n", ret);
        return ret;
    }
    
    for (int i = 0; i < iterations; i++) {
        curve25519_key key;
        
        printf("Iteration %d:\n", i + 1);
        
        // Initialize the key structure
        ret = wc_curve25519_init_ex(&key, g_heap_hint, INVALID_DEVID);
        if (ret != 0) {
            printf("FAIL wc_curve25519_init_ex: %d\n", ret);
            break;
        }
        
        // Run our detailed timing version
        ret = curve25519_make_key_with_timing(&rng, CURVE25519_KEYSIZE, &key, &timings);
        if (ret != 0) {
            printf("FAIL curve25519_make_key_with_timing: %d\n", ret);
            wc_curve25519_free(&key);
            break;
        }
        
        // Verify the key was generated correctly
        if (!key.privSet || !key.pubSet) {
            printf("FAIL Key flags not set correctly: privSet=%d, pubSet=%d\n", 
                   key.privSet, key.pubSet);
            ret = -1;
        } else {
            printf("    SUCCESS Key generated and flags set correctly\n");
        }
        
        wc_curve25519_free(&key);
        printf("\n");
    }
    
    wc_FreeRng(&rng);
    
    // Print comprehensive statistics
    if (timings.total.count > 0) {
        printf("=== Component Timing Statistics ===\n");
        print_component_timing("Private Key Generation (wc_curve25519_make_priv)", &timings.make_priv);
        print_component_timing("Set Private Flag (key->privSet = 1)", &timings.set_priv_flag);
        print_component_timing("Public Key Generation (wc_curve25519_make_pub)", &timings.make_pub);
        print_component_timing("Set Public Flag (key->pubSet = result)", &timings.set_pub_flag);
        print_component_timing("Total Key Generation", &timings.total);
        
        printf("=== Performance Analysis ===\n");
        printf("Component breakdown as percentage of total:\n");
        printf("  Private key generation: %.2f%%\n", 
               (timings.make_priv.avg_cycles / timings.total.avg_cycles) * 100.0);
        printf("  Set private flag: %.2f%%\n", 
               (timings.set_priv_flag.avg_cycles / timings.total.avg_cycles) * 100.0);
        printf("  Public key generation: %.2f%%\n", 
               (timings.make_pub.avg_cycles / timings.total.avg_cycles) * 100.0);
        printf("  Set public flag: %.2f%%\n", 
               (timings.set_pub_flag.avg_cycles / timings.total.avg_cycles) * 100.0);
        
        printf("\nMost expensive component: ");
        if (timings.make_priv.avg_cycles > timings.make_pub.avg_cycles) {
            printf("Private key generation (%.2f cycles avg)\n", timings.make_priv.avg_cycles);
        } else {
            printf("Public key generation (%.2f cycles avg)\n", timings.make_pub.avg_cycles);
        }
        
        printf("\nOptimization potential:\n");
        double crypto_operations = timings.make_priv.avg_cycles + timings.make_pub.avg_cycles;
        double overhead = timings.set_priv_flag.avg_cycles + timings.set_pub_flag.avg_cycles;
        printf("  Cryptographic operations: %.2f%% of total\n", 
               (crypto_operations / timings.total.avg_cycles) * 100.0);
        printf("  Administrative overhead: %.2f%% of total\n", 
               (overhead / timings.total.avg_cycles) * 100.0);
    }
    
    return ret;
}

/*
 * Main test runner
 */
int main(void)
{
    printf("Curve25519 Component Timing Analysis\n");
    printf("====================================\n");
    printf("Measuring individual components of wc_curve25519_make_key\n");
    
    unsigned long program_start = rdcycle();
    
    // Setup static memory
    printf("\n[SETUP] Static Memory Initialization\n");
    if (setup_wolfssl_memory() != 0) {
        printf("FAIL Static memory setup failed\n");
        return -1;
    }
    
    int overall_result = 0;
    int iterations = 20; // Number of measurements
    
    // Component timing analysis
    if (test_curve25519_component_timing(iterations) != 0) {
        printf("FAIL Component timing analysis failed\n");
        overall_result = -1;
    }
    
    unsigned long program_end = rdcycle();
    
    printf("\n====================================\n");
    printf("Analysis Complete\n");
    printf("Total program time: %lu cycles\n", program_end - program_start);
    
    if (overall_result == 0) {
        printf("\nCOMPONENT TIMING ANALYSIS SUCCESSFUL!\n");
        printf("Key insights:\n");
        printf("- Identified most expensive component in key generation\n");
        printf("- Measured overhead of each step\n");
        printf("- Performance consistency analysis\n");
        printf("- Optimization guidance provided\n");
    } else {
        printf("\nCOMPONENT TIMING ANALYSIS FAILED\n");
        printf("Check detailed output above for issues\n");
    }
    
    return overall_result;
}