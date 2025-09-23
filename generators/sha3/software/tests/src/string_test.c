#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "compiler.h"

// Test if string.h functions are available and working
int test_string_functions() {
    printf("=== Testing Standard String Functions ===\n");
    
    // Test data
    char test_str1[] = "Hello World";
    char test_str2[] = "Hello World";
    char test_str3[] = "Different String";
    char buffer1[50];
    char buffer2[50];
    unsigned char mem_buffer1[32];
    unsigned char mem_buffer2[32];
    
    int test_passed = 0;
    int test_total = 0;
    
    // Test 1: strlen
    printf("\n--- Testing strlen ---\n");
    test_total++;
    printf("strlen(\"%s\") = ", test_str1);
    
    #ifdef __has_include
        #if __has_include(<string.h>)
            printf("string.h available, ");
        #endif
    #endif
    
    size_t len = strlen(test_str1);
    printf("%zu\n", len);
    
    if (len == 11) {
        printf("✓ strlen test PASSED\n");
        test_passed++;
    } else {
        printf("✗ strlen test FAILED (expected 11, got %zu)\n", len);
    }
    
    // Test 2: strcmp
    printf("\n--- Testing strcmp ---\n");
    test_total++;
    
    int cmp1 = strcmp(test_str1, test_str2);
    int cmp2 = strcmp(test_str1, test_str3);
    
    printf("strcmp(\"%s\", \"%s\") = %d\n", test_str1, test_str2, cmp1);
    printf("strcmp(\"%s\", \"%s\") = %d\n", test_str1, test_str3, cmp2);
    
    if (cmp1 == 0 && cmp2 != 0) {
        printf("✓ strcmp test PASSED\n");
        test_passed++;
    } else {
        printf("✗ strcmp test FAILED\n");
    }
    
    // Test 3: strcpy
    printf("\n--- Testing strcpy ---\n");
    test_total++;
    
    strcpy(buffer1, test_str1);
    printf("strcpy result: \"%s\"\n", buffer1);
    
    if (strcmp(buffer1, test_str1) == 0) {
        printf("✓ strcpy test PASSED\n");
        test_passed++;
    } else {
        printf("✗ strcpy test FAILED\n");
    }
    
    // Test 4: strncpy
    printf("\n--- Testing strncpy ---\n");
    test_total++;
    
    memset(buffer2, 0, sizeof(buffer2));  // Clear buffer first
    strncpy(buffer2, test_str1, 5);
    buffer2[5] = '\0';  // Ensure null termination
    printf("strncpy(5 chars) result: \"%s\"\n", buffer2);
    
    if (strcmp(buffer2, "Hello") == 0) {
        printf("✓ strncpy test PASSED\n");
        test_passed++;
    } else {
        printf("✗ strncpy test FAILED\n");
    }
    
    // Test 5: memset
    printf("\n--- Testing memset ---\n");
    test_total++;
    
    memset(mem_buffer1, 0xAA, 16);
    memset(mem_buffer1 + 16, 0x55, 16);
    
    printf("memset result (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", mem_buffer1[i]);
    }
    printf("\n");
    
    printf("memset result (last 16 bytes): ");
    for (int i = 16; i < 32; i++) {
        printf("%02x", mem_buffer1[i]);
    }
    printf("\n");
    
    // Verify memset worked
    int memset_ok = 1;
    for (int i = 0; i < 16; i++) {
        if (mem_buffer1[i] != 0xAA) memset_ok = 0;
    }
    for (int i = 16; i < 32; i++) {
        if (mem_buffer1[i] != 0x55) memset_ok = 0;
    }
    
    if (memset_ok) {
        printf("✓ memset test PASSED\n");
        test_passed++;
    } else {
        printf("✗ memset test FAILED\n");
    }
    
    // Test 6: memcpy
    printf("\n--- Testing memcpy ---\n");
    test_total++;
    
    memset(mem_buffer2, 0x00, 32);  // Clear destination
    memcpy(mem_buffer2, mem_buffer1, 32);
    
    printf("memcpy verification: ");
    int memcpy_ok = 1;
    for (int i = 0; i < 32; i++) {
        if (mem_buffer1[i] != mem_buffer2[i]) {
            memcpy_ok = 0;
            break;
        }
    }
    
    if (memcpy_ok) {
        printf("✓ memcpy test PASSED\n");
        test_passed++;
    } else {
        printf("✗ memcpy test FAILED\n");
    }
    
    // Test 7: memcmp
    printf("\n--- Testing memcmp ---\n");
    test_total++;
    
    int memcmp1 = memcmp(mem_buffer1, mem_buffer2, 32);
    
    // Modify one byte and test again
    mem_buffer2[10] = 0xFF;
    int memcmp2 = memcmp(mem_buffer1, mem_buffer2, 32);
    
    printf("memcmp(identical): %d\n", memcmp1);
    printf("memcmp(different): %d\n", memcmp2);
    
    if (memcmp1 == 0 && memcmp2 != 0) {
        printf("✓ memcmp test PASSED\n");
        test_passed++;
    } else {
        printf("✗ memcmp test FAILED\n");
    }
    
    // Test 8: strcat
    printf("\n--- Testing strcat ---\n");
    test_total++;
    
    strcpy(buffer1, "Hello ");
    strcat(buffer1, "RISC-V");
    printf("strcat result: \"%s\"\n", buffer1);
    
    if (strcmp(buffer1, "Hello RISC-V") == 0) {
        printf("✓ strcat test PASSED\n");
        test_passed++;
    } else {
        printf("✗ strcat test FAILED\n");
    }
    
    // Summary
    printf("\n=== String Functions Test Summary ===\n");
    printf("Tests passed: %d/%d\n", test_passed, test_total);
    
    if (test_passed == test_total) {
        printf("✓ ALL string.h functions are working correctly!\n");
        return 0;
    } else {
        printf("✗ Some string.h functions are not working properly\n");
        return -1;
    }
}

int test_function_availability() {
    printf("\n=== Function Availability Test ===\n");
    
    // Test if functions are defined (will cause compile error if not available)
    printf("Testing function symbols:\n");
    
    // These will fail to compile if functions don't exist
    void* func_ptrs[] = {
        (void*)strlen,
        (void*)strcmp,
        (void*)strcpy,
        (void*)strncpy,
        (void*)strcat,
        (void*)memset,
        (void*)memcpy,
        (void*)memcmp
    };
    
    const char* func_names[] = {
        "strlen",
        "strcmp", 
        "strcpy",
        "strncpy",
        "strcat",
        "memset",
        "memcpy",
        "memcmp"
    };
    
    int num_funcs = sizeof(func_ptrs) / sizeof(func_ptrs[0]);
    
    for (int i = 0; i < num_funcs; i++) {
        if (func_ptrs[i] != NULL) {
            printf("✓ %s: available at %p\n", func_names[i], func_ptrs[i]);
        } else {
            printf("✗ %s: NOT available\n", func_names[i]);
        }
    }
    
    return 0;
}

int test_performance_comparison() {
    printf("\n=== Performance Test ===\n");
    
    #define PERF_SIZE 1024
    unsigned char buffer1[PERF_SIZE];
    unsigned char buffer2[PERF_SIZE];
    
    // Test memset performance
    unsigned long start = rdcycle();
    memset(buffer1, 0x42, PERF_SIZE);
    unsigned long end = rdcycle();
    
    printf("memset(%d bytes): %lu cycles\n", PERF_SIZE, end - start);
    
    // Test memcpy performance
    start = rdcycle();
    memcpy(buffer2, buffer1, PERF_SIZE);
    end = rdcycle();
    
    printf("memcpy(%d bytes): %lu cycles\n", PERF_SIZE, end - start);
    
    // Test memcmp performance
    start = rdcycle();
    int cmp_result = memcmp(buffer1, buffer2, PERF_SIZE);
    end = rdcycle();
    
    printf("memcmp(%d bytes): %lu cycles (result: %d)\n", PERF_SIZE, end - start, cmp_result);
    
    return 0;
}

int main(void) {
    printf("Standard Library String Functions Test\n");
    printf("=====================================\n");
    
    unsigned long total_start = rdcycle();
    
    // Test 1: Function availability (compile-time check)
    printf("=== Phase 1: Function Availability ===\n");
    test_function_availability();
    
    // Test 2: Function correctness (runtime check)
    printf("\n=== Phase 2: Function Correctness ===\n");
    int result = test_string_functions();
    
    // Test 3: Performance measurement
    printf("\n=== Phase 3: Performance Measurement ===\n");
    test_performance_comparison();
    
    unsigned long total_end = rdcycle();
    
    printf("\n=====================================\n");
    printf("Total test time: %lu cycles\n", total_end - total_start);
    
    if (result == 0) {
        printf("✓ string.h is WORKING CORRECTLY in your environment\n");
        printf("You can safely use: strlen, strcmp, strcpy, strncpy, strcat, memset, memcpy, memcmp\n");
    } else {
        printf("✗ string.h has ISSUES in your environment\n");
        printf("Consider using WolfSSL alternatives: XMEMSET, XMEMCPY, XMEMCMP\n");
    }
    
    return result;
}