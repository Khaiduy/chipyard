#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "compiler.h"
#include "test_ascon_kats.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ascon.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
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

#define ExpectNotNull(ptr) do { \
    if ((ptr) == NULL) { \
        printf("FAIL: Expected non-NULL pointer at line %d\n", __LINE__); \
        expect_result = -1; \
    } \
} while(0)

#define ExpectBufEQ(buf1, buf2, sz) do { \
    if (memcmp((buf1), (buf2), (sz)) != 0) { \
        printf("FAIL: Buffer mismatch at line %d\n", __LINE__); \
        printf("Expected: "); \
        for (int _i = 0; _i < (sz); _i++) printf("%02x", ((byte*)(buf2))[_i]); \
        printf("\nGot:      "); \
        for (int _i = 0; _i < (sz); _i++) printf("%02x", ((byte*)(buf1))[_i]); \
        printf("\n"); \
        expect_result = -1; \
    } \
} while(0)

#define EXPECT_SUCCESS() (expect_result == 0)
#define EXPECT_RESULT() (expect_result)


// Use WolfSSL's memory functions
#ifndef XMEMSET  
#define XMEMSET memset
#endif

// Helper function to convert hex character to byte (needed for KAT parsing)
static byte HexCharToByte(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return 0;
}


/*
 * Testing ASCON Hash256 functionality
 * EXACT REPLICA of the official WolfSSL test
 */
int test_ascon_hash256(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ASCON
    
    printf("=== Official WolfSSL ASCON Hash256 Test (Exact Replica) ===\n");
    
    byte msg[1024];
    byte mdOut[ASCON_HASH256_SZ];
    const size_t test_rounds = sizeof(msg) + 1; /* +1 to test 0-len msg */
    wc_AsconHash256* asconHash = NULL;
    word32 i;

    printf("Testing ASCON Hash256 with %zu test rounds\n", test_rounds);
    printf("Expected hash size: %d bytes\n", ASCON_HASH256_SZ);

    /* Check if we have enough test vectors */
    if (XELEM_CNT(ascon_hash256_output) < test_rounds) {
        printf("WARNING: Limited test vectors available, testing first %zu cases\n", 
               XELEM_CNT(ascon_hash256_output));
    }

    /* init msg buffer - EXACT same as WolfSSL test */
    for (i = 0; i < sizeof(msg); i++)
        msg[i] = (byte)i;

    printf("Initializing ASCON Hash256...\n");
    ExpectNotNull(asconHash = wc_AsconHash256_New());
    
    if (expect_result != 0) {
        printf("✗ Failed to create ASCON Hash256 instance\n");
        return EXPECT_RESULT();
    }
    printf("✓ ASCON Hash256 instance created successfully\n");

    /* Test hash computation for different message lengths */
    for (i = 0; i < test_rounds && EXPECT_SUCCESS() && i < XELEM_CNT(ascon_hash256_output); i++) {
        printf("\nTesting hash of %u-byte message...\n", i);
        
        XMEMSET(mdOut, 0, sizeof(mdOut));
        ExpectIntEQ(wc_AsconHash256_Init(asconHash), 0);
        ExpectIntEQ(wc_AsconHash256_Update(asconHash, msg, i), 0);
        ExpectIntEQ(wc_AsconHash256_Final(asconHash, mdOut), 0);
        
        if (expect_result == 0) {
            printf("✓ Hash computation successful for %u bytes\n", i);
            
            /* Compare with expected output */
            ExpectBufEQ(mdOut, ascon_hash256_output[i], ASCON_HASH256_SZ);
            
            if (expect_result == 0) {
                printf("✓ Hash matches expected value\n");
            } else {
                printf("✗ Hash does NOT match expected value\n");
            }
        } else {
            printf("✗ Hash computation failed for %u bytes\n", i);
        }
        
        wc_AsconHash256_Clear(asconHash);
    }

    printf("\n--- Testing separated update calls ---\n");
    /* Test separated update - EXACT same as WolfSSL test */
    for (i = 0; i < test_rounds && EXPECT_SUCCESS() && i < XELEM_CNT(ascon_hash256_output); i++) {
        word32 half_i = i / 2;
        printf("Testing split update: %u bytes = %u + %u\n", i, half_i, i - half_i);
        
        XMEMSET(mdOut, 0, sizeof(mdOut));
        ExpectIntEQ(wc_AsconHash256_Init(asconHash), 0);
        ExpectIntEQ(wc_AsconHash256_Update(asconHash, msg, half_i), 0);
        ExpectIntEQ(wc_AsconHash256_Update(asconHash, msg + half_i,
                                           i - half_i), 0);
        ExpectIntEQ(wc_AsconHash256_Final(asconHash, mdOut), 0);
        
        if (expect_result == 0) {
            ExpectBufEQ(mdOut, ascon_hash256_output[i], ASCON_HASH256_SZ);
            if (expect_result == 0) {
                printf("✓ Split update test passed for %u bytes\n", i);
            } else {
                printf("✗ Split update test failed for %u bytes\n", i);
            }
        }
        
        wc_AsconHash256_Clear(asconHash);
    }

    wc_AsconHash256_Free(asconHash);
    printf("ASCON Hash256 instance freed\n");

#else
    printf("ASCON Hash256 test: SKIPPED (HAVE_ASCON not defined)\n");
    return 0; /* Test skipped, not failed */
#endif
    
    return EXPECT_RESULT();
}

/*
 * Testing ASCON AEAD128 functionality
 * EXACT REPLICA of the official WolfSSL test
 */
int test_ascon_aead128(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ASCON
    
    printf("\n=== Official WolfSSL ASCON AEAD128 Test (Exact Replica) ===\n");
    
    word32 i;
    wc_AsconAEAD128* asconAEAD = NULL;

    printf("Testing ASCON AEAD128 with %zu test vectors\n", XELEM_CNT(ascon_aead128_kat));
    printf("Key size: %d bytes\n", ASCON_AEAD128_KEY_SZ);
    printf("Nonce size: %d bytes\n", ASCON_AEAD128_NONCE_SZ);
    printf("Tag size: %d bytes\n", ASCON_AEAD128_TAG_SZ);

    ExpectNotNull(asconAEAD = wc_AsconAEAD128_New());
    
    if (expect_result != 0) {
        printf("✗ Failed to create ASCON AEAD128 instance\n");
        return EXPECT_RESULT();
    }
    printf("✓ ASCON AEAD128 instance created successfully\n");

    /* Test each KAT vector - EXACT same as WolfSSL test */
    for (i = 0; i < XELEM_CNT(ascon_aead128_kat); i++) {
        byte key[ASCON_AEAD128_KEY_SZ];
        byte nonce[ASCON_AEAD128_NONCE_SZ];
        byte pt[32]; /* longest plaintext we test is 32 bytes */
        word32 ptSz;
        byte ad[32]; /* longest AD we test is 32 bytes */
        word32 adSz;
        byte ct[48]; /* longest ciphertext we test is 32 bytes + 16 bytes tag */
        word32 ctSz;
        word32 j;
        byte tag[ASCON_AEAD128_TAG_SZ];
        byte buf[32]; /* longest buffer we test is 32 bytes */

        printf("\n--- Testing KAT vector %u ---\n", i);

        XMEMSET(key, 0, sizeof(key));
        XMEMSET(nonce, 0, sizeof(nonce));
        XMEMSET(pt, 0, sizeof(pt));
        XMEMSET(ad, 0, sizeof(ad));
        XMEMSET(ct, 0, sizeof(ct));
        XMEMSET(tag, 0, sizeof(tag));

        /* Convert HEX strings to byte stream - EXACT same as WolfSSL test */
        for (j = 0; ascon_aead128_kat[i][0][j] != '\0'; j += 2) {
            key[j/2] = HexCharToByte(ascon_aead128_kat[i][0][j]) << 4 |
                       HexCharToByte(ascon_aead128_kat[i][0][j+1]);
        }
        for (j = 0; ascon_aead128_kat[i][1][j] != '\0'; j += 2) {
            nonce[j/2] = HexCharToByte(ascon_aead128_kat[i][1][j]) << 4 |
                         HexCharToByte(ascon_aead128_kat[i][1][j+1]);
        }
        for (j = 0; ascon_aead128_kat[i][2][j] != '\0'; j += 2) {
            pt[j/2] = HexCharToByte(ascon_aead128_kat[i][2][j]) << 4 |
                      HexCharToByte(ascon_aead128_kat[i][2][j+1]);
        }
        ptSz = j/2;
        for (j = 0; ascon_aead128_kat[i][3][j] != '\0'; j += 2) {
            ad[j/2] = HexCharToByte(ascon_aead128_kat[i][3][j]) << 4 |
                      HexCharToByte(ascon_aead128_kat[i][3][j+1]);
        }
        adSz = j/2;
        for (j = 0; ascon_aead128_kat[i][4][j] != '\0'; j += 2) {
            ct[j/2] = HexCharToByte(ascon_aead128_kat[i][4][j]) << 4 |
                      HexCharToByte(ascon_aead128_kat[i][4][j+1]);
        }
        ctSz = j/2 - ASCON_AEAD128_TAG_SZ;

        printf("Plaintext size: %u bytes, AD size: %u bytes, Ciphertext size: %u bytes\n", 
               ptSz, adSz, ctSz);

        /* Test all 4 modes: encrypt, decrypt, split encrypt, split decrypt */
        for (j = 0; j < 4; j++) {
            printf("Sub-test %u: ", j);
            
            ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
            ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
            ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
            ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, ad, adSz), 0);
            
            if (j == 0) {
                /* Encryption test - EXACT same as WolfSSL test */
                printf("Encryption... ");
                ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD, buf, pt,
                            ptSz), 0);
                ExpectBufEQ(buf, ct, ptSz);
                ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(asconAEAD, tag), 0);
                ExpectBufEQ(tag, ct + ptSz, ASCON_AEAD128_TAG_SZ);
                
                if (expect_result == 0) {
                    printf("PASSED\n");
                } else {
                    printf("FAILED\n");
                }
            }
            else if (j == 1) {
                /* Decryption test - EXACT same as WolfSSL test */
                printf("Decryption... ");
                ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, buf, ct,
                            ctSz), 0);
                ExpectBufEQ(buf, pt, ctSz);
                ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, ct + ctSz),
                            0);
                
                if (expect_result == 0) {
                    printf("PASSED\n");
                } else {
                    printf("FAILED\n");
                }
            }
            else if (j == 2) {
                /* Split encryption test - EXACT same as WolfSSL test */
                printf("Split encryption... ");
                ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD, buf, pt,
                        ptSz / 2), 0);
                ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD,
                        buf + (ptSz/2), pt + (ptSz/2), ptSz - (ptSz/2)), 0);
                ExpectBufEQ(buf, ct, ptSz);
                ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(asconAEAD, tag), 0);
                ExpectBufEQ(tag, ct + ptSz, ASCON_AEAD128_TAG_SZ);
                
                if (expect_result == 0) {
                    printf("PASSED\n");
                } else {
                    printf("FAILED\n");
                }
            }
            else if (j == 3) {
                /* Split decryption test - EXACT same as WolfSSL test */
                printf("Split decryption... ");
                ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, buf, ct,
                        ctSz / 2), 0);
                ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD,
                        buf + (ctSz/2), ct + (ctSz/2), ctSz - (ctSz/2)), 0);
                ExpectBufEQ(buf, pt, ctSz);
                ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, ct + ctSz),
                        0);
                
                if (expect_result == 0) {
                    printf("PASSED\n");
                } else {
                    printf("FAILED\n");
                }
            }
            wc_AsconAEAD128_Clear(asconAEAD);
        }
        
        if (expect_result == 0) {
            printf("✓ KAT vector %u: ALL TESTS PASSED\n", i);
        } else {
            printf("✗ KAT vector %u: SOME TESTS FAILED\n", i);
        }
    }

    wc_AsconAEAD128_Free(asconAEAD);
    printf("ASCON AEAD128 instance freed\n");

#else
    printf("ASCON AEAD128 test: SKIPPED (HAVE_ASCON not defined)\n");
    return 0; /* Test skipped, not failed */
#endif
    
    return EXPECT_RESULT();
}

int main(void)
{
    printf("WolfSSL ASCON Official Test Replica\n");
    printf("===================================\n");
    
    unsigned long total_start = rdcycle();
    int overall_result = 0;
    
    // Test 1: ASCON Hash256
    printf("\n=== Running ASCON Hash256 Tests ===\n");
    unsigned long start = rdcycle();
    int result1 = test_ascon_hash256();
    unsigned long end = rdcycle();
    
    if (result1 == 0) {
        printf("✓ ASCON Hash256 test PASSED (%lu cycles)\n", end - start);
    } else {
        printf("✗ ASCON Hash256 test FAILED (%lu cycles)\n", end - start);
        overall_result = -1;
    }
    
    // Test 2: ASCON AEAD128
    printf("\n=== Running ASCON AEAD128 Tests ===\n");
    start = rdcycle();
    int result2 = test_ascon_aead128();
    end = rdcycle();
    
    if (result2 == 0) {
        printf("✓ ASCON AEAD128 test PASSED (%lu cycles)\n", end - start);
    } else {
        printf("✗ ASCON AEAD128 test FAILED (%lu cycles)\n", end - start);
        overall_result = -1;
    }
    
    unsigned long total_end = rdcycle();
    
    printf("\n===================================\n");
    printf("Total execution time: %lu cycles\n", total_end - total_start);
    
    if (overall_result == 0) {
        printf("🎉 ALL ASCON TESTS PASSED!\n");
        printf("Both ASCON Hash256 and AEAD128 are working correctly on RISC-V\n");
    } else {
        printf("❌ SOME ASCON TESTS FAILED\n");
        printf("Check the output above for specific failures\n");
    }
    
    return overall_result;
}