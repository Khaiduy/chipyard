#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "compiler.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef XMEMSET  
#define XMEMSET memset
#endif
enum {
    drbgInitC     = 0,
    drbgReseed    = 1,
    drbgGenerateW = 2,
    drbgGenerateH = 3,
    drbgInitV     = 4
};

typedef struct DRBG_internal DRBG_internal;

// Test the specific DRBG memory allocation logic from lines 1726-1740
int test_drbg_memory_allocation(void)
{
    printf("\n=== DRBG Memory Allocation Test ===\n");
    
    WC_RNG rng;
    XMEMSET(&rng, 0, sizeof(rng));
    
    printf("Testing DRBG memory allocation logic...\n");
    
    // Show the size that will be allocated
    printf("DRBG_internal size: %zu bytes\n", sizeof(DRBG_internal));
    
    // Test the memory allocation path that happens in _InitRng
    printf("Simulating the allocation from lines 1726-1740:\n");
    
#if !defined(WOLFSSL_NO_MALLOC) || defined(WOLFSSL_STATIC_MEMORY)
    printf("✅ Memory allocation path enabled\n");
    printf("   Will use XMALLOC for DRBG allocation\n");
    
    // Test if we can allocate the DRBG structure directly
    void* test_drbg = XMALLOC(sizeof(DRBG_internal), NULL, DYNAMIC_TYPE_RNG);
    if (test_drbg == NULL) {
        printf("❌ XMALLOC failed to allocate DRBG_internal (%zu bytes)\n", 
               sizeof(DRBG_internal));
        printf("   This is exactly what causes MEMORY_E (-125) in _InitRng\n");
        return -125; // MEMORY_E
    } else {
        printf("✅ XMALLOC successfully allocated DRBG_internal (%zu bytes)\n", 
               sizeof(DRBG_internal));
        XFREE(test_drbg, NULL, DYNAMIC_TYPE_RNG);
        printf("✅ XFREE completed successfully\n");
    }
#else
    printf("✅ Static allocation path enabled\n");
    printf("   Will use rng->drbg_data for DRBG allocation\n");
    printf("   This path should not fail with MEMORY_E\n");
#endif

    // Now test the actual wc_InitRng to see if it fails at this point
    printf("\nTesting actual wc_InitRng...\n");
    int ret = wc_InitRng(&rng);
    printf("wc_InitRng returned: %d\n", ret);
    
    if (ret == -125) {
        printf("❌ CONFIRMED: wc_InitRng fails with MEMORY_E at DRBG allocation\n");
        printf("   The failure occurs at lines 1726-1740 in random.c\n");
        printf("   XMALLOC(sizeof(DRBG_internal), rng->heap, DYNAMIC_TYPE_RNG) failed\n");
    } else if (ret == 0) {
        printf("✅ wc_InitRng succeeded - DRBG allocated successfully\n");
        wc_FreeRng(&rng);
    } else {
        printf("⚠ wc_InitRng failed with different error: %d\n", ret);
    }
    
    return ret;
}

// Test memory pressure scenarios
int test_memory_pressure_drbg(void)
{
    printf("\n=== DRBG Memory Pressure Test ===\n");
    
    // Allocate progressively larger blocks to simulate memory pressure
    size_t drbg_size = sizeof(DRBG_internal);
    printf("DRBG_internal requires %zu bytes\n", drbg_size);
    
    // Test multiple DRBG allocations
    void* drbg_ptrs[10];
    int successful_allocs = 0;
    
    printf("Testing multiple DRBG allocations...\n");
    for (int i = 0; i < 10; i++) {
        drbg_ptrs[i] = XMALLOC(drbg_size, NULL, DYNAMIC_TYPE_RNG);
        if (drbg_ptrs[i] != NULL) {
            successful_allocs++;
            printf("  Allocation %d: ✅ Success\n", i + 1);
        } else {
            printf("  Allocation %d: ❌ Failed\n", i + 1);
            break;
        }
    }
    
    printf("Successfully allocated %d DRBG structures\n", successful_allocs);
    
    // Free all successful allocations
    for (int i = 0; i < successful_allocs; i++) {
        XFREE(drbg_ptrs[i], NULL, DYNAMIC_TYPE_RNG);
    }
    
    if (successful_allocs < 3) {
        printf("❌ Critical: Can't allocate multiple DRBG structures\n");
        printf("   Your system has severe memory constraints\n");
        return -125;
    }
    
    printf("✅ Memory pressure test passed\n");
    return 0;
}

// Test the exact conditions from the code
int test_exact_drbg_allocation_path(void)
{
    printf("\n=== Exact DRBG Allocation Path Test ===\n");
    
    // Simulate the exact conditions in _InitRng when it reaches the allocation
    WC_RNG rng;
    XMEMSET(&rng, 0, sizeof(rng));
    
    // Set up the same conditions as in _InitRng
    rng.heap = NULL;  // This is what gets passed to XMALLOC
    
    printf("Simulating exact allocation from _InitRng:\n");
    printf("rng->heap = %p\n", rng.heap);
    printf("DYNAMIC_TYPE_RNG = %d\n", DYNAMIC_TYPE_RNG);
    printf("sizeof(DRBG_internal) = %zu\n", sizeof(DRBG_internal));
    
#if !defined(WOLFSSL_NO_MALLOC) || defined(WOLFSSL_STATIC_MEMORY)
    printf("\nExecuting: rng->drbg = XMALLOC(sizeof(DRBG_internal), rng->heap, DYNAMIC_TYPE_RNG)\n");
    
    struct DRBG* test_drbg = (struct DRBG*)XMALLOC(sizeof(DRBG_internal), 
                                                   rng.heap, 
                                                   DYNAMIC_TYPE_RNG);
    
    if (test_drbg == NULL) {
        printf("❌ ALLOCATION FAILED - This is the exact failure in _InitRng!\n");
        printf("   The condition 'if (rng->drbg == NULL)' will be TRUE\n");
        printf("   Setting ret = MEMORY_E; rng->status = DRBG_FAILED;\n");
        return -125; // MEMORY_E
    } else {
        printf("✅ ALLOCATION SUCCEEDED\n");
        printf("   rng->drbg = %p\n", test_drbg);
        printf("   The allocation path works correctly\n");
        
        XFREE(test_drbg, rng.heap, DYNAMIC_TYPE_RNG);
        printf("✅ Free completed successfully\n");
    }
#else
    printf("Static allocation path: rng->drbg = (struct DRBG*)&rng->drbg_data\n");
    printf("✅ This path cannot fail with MEMORY_E\n");
#endif
    
    return 0;
}

int main(void)
{
    printf("DRBG Memory Allocation Test\n");
    printf("===========================\n");
    printf("Testing the specific code from random.c lines 1726-1740\n");
    
    unsigned long start = rdcycle();
    
    // Test 1: Basic DRBG allocation
    int ret1 = test_drbg_memory_allocation();
    printf("\nTest 1 result: %d\n", ret1);
    
    // Test 2: Memory pressure
    int ret2 = test_memory_pressure_drbg();
    printf("Test 2 result: %d\n", ret2);
    
    // Test 3: Exact allocation path
    int ret3 = test_exact_drbg_allocation_path();
    printf("Test 3 result: %d\n", ret3);
    
    unsigned long end = rdcycle();
    
    printf("\n===========================\n");
    printf("DRBG allocation test took %lu cycles\n", end - start);
    
    // Final diagnosis
    printf("\n🔍 FINAL DIAGNOSIS:\n");
    if (ret1 == -125 || ret2 == -125 || ret3 == -125) {
        printf("❌ CONFIRMED: DRBG allocation fails due to insufficient memory\n");
        printf("   The exact failure point is lines 1726-1740 in random.c\n");
        printf("   XMALLOC(sizeof(DRBG_internal), rng->heap, DYNAMIC_TYPE_RNG) returns NULL\n");
        
        printf("\n💡 SOLUTIONS:\n");
        printf("1. Increase heap size in linker script\n");
        printf("2. Initialize static memory pool with wolfSSL_InitMemory()\n");
        printf("3. Use -DWOLFSSL_GENSEED_FORTEST for simpler RNG\n");
        printf("4. Rebuild with -DWC_NO_HASHDRBG to disable Hash-DRBG\n");
    } else {
        printf("✅ DRBG allocation works correctly\n");
        printf("   The memory allocation in lines 1726-1740 succeeds\n");
        printf("   Your -125 error must come from elsewhere in _InitRng\n");
    }
    
    return (ret1 == -125 || ret2 == -125 || ret3 == -125) ? -125 : 0;
}