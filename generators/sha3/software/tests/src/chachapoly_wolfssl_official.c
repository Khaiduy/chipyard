#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "compiler.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/types.h>


// WolfSSL-style test macros (replicated from their framework)
#define EXPECT_DECLS int expect_result = 0
#define ExpectIntEQ(a, b) do { \
    int _a = (a); \
    int _b = (b); \
    if (_a != _b) { \
        printf("FAIL: Expected %d, got %d at line %d\n", _b, _a, __LINE__); \
        expect_result = -1; \
    } \
} while(0)

#define EXPECT_RESULT() (expect_result)
#define WC_NO_ERR_TRACE(x) (x)

// Use WolfSSL's memory functions
#ifndef XMEMCMP
#define XMEMCMP memcmp
#endif

#ifndef XMEMSET  
#define XMEMSET memset
#endif

// Static memory setup
#define HEAP_SIZE 65536
static unsigned char gHeap[HEAP_SIZE];
static WOLFSSL_HEAP_HINT* gHeapHint = NULL;

static int setup_static_memory(void)
{
    EXPECT_DECLS;
    
    XMEMSET(gHeap, 0, sizeof(gHeap));
    
    ExpectIntEQ(wc_LoadStaticMemory(&gHeapHint, gHeap, sizeof(gHeap), 
                                    WOLFMEM_GENERAL, 10), 0);
    
    if (expect_result == 0) {
        wolfSSL_SetGlobalHeapHint(gHeapHint);
        printf("WolfSSL static memory initialized (heap size: %d bytes)\n", HEAP_SIZE);
    }
    
    return EXPECT_RESULT();
}

/*
 * Testing wc_ChaCha20Poly1305_Encrypt() and wc_ChaCha20Poly1305_Decrypt()
 * EXACT REPLICA of the official WolfSSL test
 */
int test_wc_ChaCha20Poly1305_aead(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    
    printf("=== Official WolfSSL ChaCha20Poly1305 Test (Exact Replica) ===\n");
    
    // EXACT same test vectors from WolfSSL official test
    const byte  key[] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    
    const byte  plaintext[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };
    
    const byte  iv[] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    
    const byte  aad[] = { /* additional data */
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };
    
    const byte  cipher[] = { /* expected output from operation */
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    
    const byte  authTag[] = { /* expected output from operation */
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };
    
    byte        generatedCiphertext[272];
    byte        generatedPlaintext[272];
    byte        generatedAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    /* Initialize stack variables. */
    XMEMSET(generatedCiphertext, 0, 272);
    XMEMSET(generatedPlaintext, 0, 272);

    printf("Plaintext: \"");
    for (int i = 0; i < sizeof(plaintext); i++) {
        if (plaintext[i] >= 32 && plaintext[i] <= 126) {
            printf("%c", plaintext[i]);
        } else {
            printf(".");
        }
    }
    printf("\"\n");

    printf("Key size: %zu bytes\n", sizeof(key));
    printf("Nonce size: %zu bytes\n", sizeof(iv));
    printf("AAD size: %zu bytes\n", sizeof(aad));
    printf("Plaintext size: %zu bytes\n", sizeof(plaintext));
    
    /* Test Encrypt - EXACT same as WolfSSL official test */
    printf("\nTesting wc_ChaCha20Poly1305_Encrypt...\n");
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
        plaintext, sizeof(plaintext), generatedCiphertext, generatedAuthTag),
        0);
        
    if (expect_result == 0) {
        printf("✓ Encryption successful\n");
        
        // Verify ciphertext matches expected - EXACT same as WolfSSL test
        ExpectIntEQ(XMEMCMP(generatedCiphertext, cipher,
            sizeof(cipher)/sizeof(byte)), 0);
            
        if (expect_result == 0) {
            printf("✓ Generated ciphertext matches expected value\n");
        } else {
            printf("✗ Generated ciphertext does NOT match expected value\n");
            printf("Expected: ");
            for (int i = 0; i < sizeof(cipher); i++) {
                printf("%02x", cipher[i]);
            }
            printf("\nGot:      ");
            for (int i = 0; i < sizeof(cipher); i++) {
                printf("%02x", generatedCiphertext[i]);
            }
            printf("\n");
        }
        
        // Verify auth tag matches expected - EXACT same as WolfSSL test
        ExpectIntEQ(XMEMCMP(generatedAuthTag, authTag,
            sizeof(authTag)/sizeof(byte)), 0);
            
        if (expect_result == 0) {
            printf("✓ Generated auth tag matches expected value\n");
        } else {
            printf("✗ Generated auth tag does NOT match expected value\n");
            printf("Expected tag: ");
            for (int i = 0; i < sizeof(authTag); i++) {
                printf("%02x", authTag[i]);
            }
            printf("\nGot tag:      ");
            for (int i = 0; i < sizeof(authTag); i++) {
                printf("%02x", generatedAuthTag[i]);
            }
            printf("\n");
        }
    } else {
        printf("✗ Encryption failed\n");
        return EXPECT_RESULT();
    }

    /* Test bad args for encrypt - EXACT same as WolfSSL official test */
    printf("\nTesting bad arguments for wc_ChaCha20Poly1305_Encrypt...\n");
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(NULL, iv, aad, sizeof(aad),
        plaintext, sizeof(plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, NULL, aad, sizeof(aad),
        plaintext, sizeof(plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad), NULL,
        sizeof(plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
        NULL, sizeof(plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
        plaintext, sizeof(plaintext), NULL, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
        plaintext, sizeof(plaintext), generatedCiphertext, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    if (expect_result == 0) {
        printf("✓ All bad argument tests for encryption passed\n");
    } else {
        printf("✗ Some bad argument tests for encryption failed\n");
    }

    /* Test Decrypt - EXACT same as WolfSSL official test */
    printf("\nTesting wc_ChaCha20Poly1305_Decrypt...\n");
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad), cipher,
        sizeof(cipher), authTag, generatedPlaintext), 0);
        
    if (expect_result == 0) {
        printf("✓ Decryption successful\n");
        
        ExpectIntEQ(XMEMCMP(generatedPlaintext, plaintext,
            sizeof(plaintext)/sizeof(byte)), 0);
            
        if (expect_result == 0) {
            printf("✓ Decrypted plaintext matches original\n");
            printf("Decrypted: \"");
            for (int i = 0; i < sizeof(plaintext); i++) {
                if (generatedPlaintext[i] >= 32 && generatedPlaintext[i] <= 126) {
                    printf("%c", generatedPlaintext[i]);
                } else {
                    printf(".");
                }
            }
            printf("\"\n");
        } else {
            printf("✗ Decrypted plaintext does NOT match original\n");
        }
    } else {
        printf("✗ Decryption failed\n");
    }

    /* Test bad args for decrypt - EXACT same as WolfSSL official test */
    printf("\nTesting bad arguments for wc_ChaCha20Poly1305_Decrypt...\n");
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(NULL, iv, aad, sizeof(aad), cipher,
        sizeof(cipher), authTag, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, NULL, aad, sizeof(aad),
        cipher, sizeof(cipher), authTag, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad), NULL,
        sizeof(cipher), authTag, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad), cipher,
        sizeof(cipher), NULL, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad), cipher,
        sizeof(cipher), authTag, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad), NULL,
        sizeof(cipher), authTag, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    if (expect_result == 0) {
        printf("✓ All bad argument tests for decryption passed\n");
    } else {
        printf("✗ Some bad argument tests for decryption failed\n");
    }

#else
    printf("ChaCha20-Poly1305 test: SKIPPED (HAVE_CHACHA or HAVE_POLY1305 not defined)\n");
    return 0; /* Test skipped, not failed */
#endif
    
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_aead */

int main(void)
{
    printf("WolfSSL ChaCha20-Poly1305 Official Test Replica\n");
    printf("===============================================\n");
    
    // Setup static memory for bare-metal RISC-V
    if (setup_static_memory() != 0) {
        printf("✗ Static memory setup FAILED\n");
        return -1;
    }
    
    unsigned long start = rdcycle();
    
    // Run the exact replica of official WolfSSL test
    int result = test_wc_ChaCha20Poly1305_aead();
    
    unsigned long end = rdcycle();
    
    printf("\n===============================================\n");
    printf("Test execution took %lu cycles\n", end - start);
    
    if (result == 0) {
        printf("🎉 OFFICIAL WOLFSSL TEST REPLICA: ALL TESTS PASSED!\n");
        printf("ChaCha20-Poly1305 is working correctly on RISC-V\n");
    } else {
        printf("❌ OFFICIAL WOLFSSL TEST REPLICA: TESTS FAILED\n");
        printf("ChaCha20-Poly1305 has issues on RISC-V\n");
    }
    
    return result;
}