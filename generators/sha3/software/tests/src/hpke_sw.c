/* hpke_sw.c
 * Pure software HPKE implementation for performance comparison
 * Using original WolfSSL functions in same structure as hardware version
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
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifndef XMEMSET  
#define XMEMSET memset
#endif

#ifndef XMEMCPY
#define XMEMCPY memcpy
#endif

#ifndef XMEMCMP
#define XMEMCMP memcmp
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
static unsigned long total_cycles = 0;
static unsigned long step_start_cycles = 0;

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
    printf("  SW Timing: %s took %lu cycles\n", operation, elapsed);
}

/* Setup static memory */
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

/* Helper function to print hex values - FULL LENGTH */
static void print_hex_debug(const char* label, const byte* data, int len)
{
    printf("    %s (%d bytes):\n      ", label, len);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i != len - 1) {
            printf("\n      ");  /* New line every 16 bytes */
        }
    }
    printf("\n");
}

/* Helper function to print complete key information */
static void print_key_debug(const char* label, curve25519_key* key)
{
    printf("  === %s ===\n", label);
    if (key->privSet) {
        print_hex_debug("Private key (32 bytes)", key->k, CURVE25519_KEYSIZE);
    }
    if (key->pubSet) {
        print_hex_debug("Public key (32 bytes)", key->p.point, CURVE25519_KEYSIZE);
    }
    printf("  privSet=%d, pubSet=%d\n", key->privSet, key->pubSet);
}

/* Modified sw_HpkeDh with debug output */
static int sw_HpkeDh(Hpke* hpke, void* ephemeralKey, void* receiverKey, byte* sharedSecret)
{
    if (hpke == NULL || ephemeralKey == NULL || receiverKey == NULL || sharedSecret == NULL)
        return BAD_FUNC_ARG;

    if (hpke->kem != DHKEM_X25519_HKDF_SHA256)
        return BAD_FUNC_ARG;

    curve25519_key* ephKey = (curve25519_key*)ephemeralKey;
    curve25519_key* recvKey = (curve25519_key*)receiverKey;
    word32 sharedSecretSz = CURVE25519_KEYSIZE;

    printf("  === Performing DH operation with software ===\n");
    
    /* Debug: Print input keys */
    print_key_debug("Ephemeral Key for DH", ephKey);
    print_key_debug("Receiver Key for DH", recvKey);
    
    /* Use ORIGINAL WolfSSL shared secret computation */
    printf("    Computing: shared_secret = ephemeral_private * receiver_public\n");
    start_timing();
    int ret = wc_curve25519_shared_secret_ex(ephKey, recvKey, sharedSecret, &sharedSecretSz, EC25519_LITTLE_ENDIAN);
    end_timing("Software Curve25519 shared secret");
    
    if (ret == 0) {
        print_hex_debug("DH shared secret result", sharedSecret, CURVE25519_KEYSIZE);
    } else {
        printf("    DH operation failed: %d\n", ret);
    }
    
    return ret;
}

/* Modified sw_HpkeExtractAndExpand with debug output */
static int sw_HpkeExtractAndExpand(Hpke* hpke, byte* dh, word32 dhSz,
                                   byte* kemContext, word32 kemContextSz,
                                   byte* sharedSecret)
{
    int ret;
    byte prkExtract[WC_SHA256_DIGEST_SIZE];
    
    printf("  === Extract and Expand operation DEBUG ===\n");
    
    /* Debug: Print inputs */
    print_hex_debug("Input DH", dh, dhSz);
    print_hex_debug("Input KEM context", kemContext, kemContextSz);
    
    /* Step 1: Extract */
    printf("    HKDF Extract step\n");
    start_timing();
    ret = wc_HKDF_Extract(WC_SHA256, 
                          NULL, 0,  /* No salt */
                          dh, dhSz, 
                          prkExtract);
    end_timing("HKDF Extract");
    
    if (ret != 0) {
        printf("    HKDF Extract failed: %d\n", ret);
        return ret;
    }
    
    /* Debug: Print extract result */
    print_hex_debug("PRK after Extract", prkExtract, sizeof(prkExtract));
    
    /* Step 2: Expand */
    printf("    HKDF Expand step\n");
    start_timing();
    ret = wc_HKDF_Expand(WC_SHA256, 
                         prkExtract, sizeof(prkExtract),
                         kemContext, kemContextSz,
                         sharedSecret, CURVE25519_KEYSIZE);
    end_timing("HKDF Expand");
    
    if (ret != 0) {
        printf("    HKDF Expand failed: %d\n", ret);
        return ret;
    }
    
    /* Debug: Print expand result */
    print_hex_debug("Shared secret after Expand", sharedSecret, CURVE25519_KEYSIZE);
    printf("  === Extract and Expand completed successfully ===\n");
    return 0;
}

/* Modified sw_HpkeEncap with complete debug output */
static int sw_HpkeEncap(Hpke* hpke, void* ephemeralKey, void* receiverKey, 
                        byte* sharedSecret)
{
    int ret;
    byte dh[CURVE25519_KEYSIZE];
    byte kemContext[2 * CURVE25519_KEYSIZE];  /* ephemeral_pk || receiver_pk */
    curve25519_key* ephKey = (curve25519_key*)ephemeralKey;
    curve25519_key* recvKey = (curve25519_key*)receiverKey;
    
    printf("  === HPKE Encapsulation DEBUG ===\n");
    
    /* Debug: Print input keys */
    print_key_debug("Ephemeral Key Input", ephKey);
    print_key_debug("Receiver Key Input", recvKey);
    
    /* Step 1: DH operation with software */
    printf("    Step 1: DH operation\n");
    ret = sw_HpkeDh(hpke, ephemeralKey, receiverKey, dh);
    if (ret != 0) {
        printf("    DH operation failed: %d\n", ret);
        return ret;
    }
    
    /* Step 2: Create KEM context (ephemeral_pk || receiver_pk) */
    printf("    Step 2: Create KEM context\n");
    XMEMCPY(kemContext, ephKey->p.point, CURVE25519_KEYSIZE);
    XMEMCPY(kemContext + CURVE25519_KEYSIZE, recvKey->p.point, CURVE25519_KEYSIZE);
    
    /* Debug: Print KEM context components */
    print_hex_debug("Ephemeral public key", ephKey->p.point, CURVE25519_KEYSIZE);
    print_hex_debug("Receiver public key", recvKey->p.point, CURVE25519_KEYSIZE);
    print_hex_debug("KEM context (eph_pk || recv_pk)", kemContext, sizeof(kemContext));
    
    /* Step 3: Extract and Expand */
    printf("    Step 3: Extract and Expand\n");
    ret = sw_HpkeExtractAndExpand(hpke, dh, sizeof(dh), 
                                  kemContext, sizeof(kemContext),
                                  sharedSecret);
    
    if (ret == 0) {
        /* Debug: Print final shared secret */
        print_hex_debug("Final HPKE shared secret", sharedSecret, CURVE25519_KEYSIZE);
        printf("  === Encapsulation completed successfully ===\n");
    } else {
        printf("  Encapsulation failed: %d\n", ret);
    }
    
    return ret;
}

/* Modified sw_HpkeKeyScheduleBase with debug output */
static int sw_HpkeKeyScheduleBase(Hpke* hpke, byte* sharedSecret, 
                                  const byte* info, word32 infoSz,
                                  byte* key, byte* baseNonce)
{
    int ret;
    byte prkSchedule[WC_SHA256_DIGEST_SIZE];
    byte keyScheduleContext[1 + infoSz];  /* mode || info */
    byte keyInfo[4] = {0x00, 0x01, 0x00, 0x10};  /* "key" + length 16 */
    byte nonceInfo[7] = {0x00, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x00};  /* "base_nonce" + length 12 */
    
    // printf("  === HPKE Key Schedule Base DEBUG ===\n");
    
    /* Debug: Print inputs */
    // print_hex_debug("Input shared secret", sharedSecret, CURVE25519_KEYSIZE);
    if (info != NULL && infoSz > 0) {
        // print_hex_debug("Info parameter", info, infoSz);
    }
    
    /* Create key schedule context: mode (0x00 for base) || info */
    keyScheduleContext[0] = 0x00;  /* Base mode */
    if (info != NULL && infoSz > 0) {
        XMEMCPY(keyScheduleContext + 1, info, infoSz);
    }
    
    // print_hex_debug("Key schedule context", keyScheduleContext, 1 + infoSz);
    
    /* Step 1: Schedule Extract */
    // printf("    Schedule Extract step\n");
    // start_timing();
    ret = wc_HKDF_Extract(WC_SHA256,
                          NULL, 0,  /* No salt */
                          sharedSecret, CURVE25519_KEYSIZE,
                          prkSchedule);
    // end_timing("Schedule HKDF Extract");
    
    if (ret != 0) {
        // printf("    Schedule Extract failed: %d\n", ret);
        return ret;
    }
    
    // print_hex_debug("PRK schedule", prkSchedule, sizeof(prkSchedule));
    
    /* Step 2: Expand for key */
    // printf("    Expand for key\n");
    // print_hex_debug("Key info", keyInfo, sizeof(keyInfo));
    // start_timing();
    ret = wc_HKDF_Expand(WC_SHA256,
                         prkSchedule, sizeof(prkSchedule),
                         keyInfo, sizeof(keyInfo),
                         key, 16);  /* AES-128 key size */
    // end_timing("Key HKDF Expand");
    
    if (ret != 0) {
        // printf("    Key expand failed: %d\n", ret);
        return ret;
    }
    
    // print_hex_debug("Derived AES key", key, 16);
    
    /* Step 3: Expand for base nonce */
    // printf("    Expand for base nonce\n");
    // print_hex_debug("Nonce info", nonceInfo, sizeof(nonceInfo));
    // start_timing();
    ret = wc_HKDF_Expand(WC_SHA256,
                         prkSchedule, sizeof(prkSchedule),
                         nonceInfo, sizeof(nonceInfo),
                         baseNonce, 12);  /* GCM nonce size */
    // end_timing("Nonce HKDF Expand");
    
    if (ret != 0) {
        // printf("    Nonce expand failed: %d\n", ret);
        return ret;
    }
    
    // print_hex_debug("Derived base nonce", baseNonce, 12);
    // printf("  === Key Schedule Base completed successfully ===\n");
    return 0;
}

/* Setup Base Sender following HPKE specification */
static int sw_HpkeSetupBaseSender(Hpke* hpke, void* ephemeralKey, void* receiverKey,
                                  const byte* info, word32 infoSz,
                                  byte* key, byte* baseNonce)
{
    int ret;
    byte sharedSecret[CURVE25519_KEYSIZE];
    
    // printf("HPKE Setup Base Sender (Software)\n");
    
    /* Step 1: Encapsulation */
    // printf("Step 1: Encapsulation\n");
    ret = sw_HpkeEncap(hpke, ephemeralKey, receiverKey, sharedSecret);
    if (ret != 0) {
        // printf("Encapsulation failed: %d\n", ret);
        return ret;
    }
    
    /* Step 2: Key Schedule */
    // printf("Step 2: Key Schedule\n");
    ret = sw_HpkeKeyScheduleBase(hpke, sharedSecret, info, infoSz, key, baseNonce);
    if (ret != 0) {
        // printf("Key Schedule failed: %d\n", ret);
        return ret;
    }
    
    // printf("Setup Base Sender completed successfully\n");
    return 0;
}

/* Setup Base Receiver following HPKE specification */
static int sw_HpkeSetupBaseReceiver(Hpke* hpke, void* receiverKey, 
                                    const byte* ephemeralPubKey, word32 ephemeralPubKeySz,
                                    const byte* info, word32 infoSz,
                                    byte* key, byte* baseNonce)
{
    int ret;
    byte sharedSecret[CURVE25519_KEYSIZE];
    byte kemContext[2 * CURVE25519_KEYSIZE];
    curve25519_key* recvKey = (curve25519_key*)receiverKey;
    
    // printf("=== HPKE Setup Base Receiver (Software) DEBUG ===\n");
    
    /* Debug: Print inputs */
    // print_key_debug("Receiver Key Input", recvKey);
    // print_hex_debug("Ephemeral public key input", ephemeralPubKey, ephemeralPubKeySz);
    if (info != NULL && infoSz > 0) {
        // print_hex_debug("Info parameter", info, infoSz);
    }
    
    if (ephemeralPubKeySz != CURVE25519_KEYSIZE) {
        // printf("Invalid ephemeral public key size: %u\n", ephemeralPubKeySz);
        return BAD_FUNC_ARG;
    }
    
    /* Step 1: DH operation with software */
    // printf("Step 1: DH operation\n");
    
    /* Create temporary key for ephemeral public key */
    curve25519_key ephKey;
    ret = wc_curve25519_init_ex(&ephKey, hpke->heap, INVALID_DEVID);
    if (ret != 0) {
        // printf("Ephemeral key init failed: %d\n", ret);
        return ret;
    }
    
    /* Set ephemeral public key */
    XMEMCPY(ephKey.p.point, ephemeralPubKey, CURVE25519_KEYSIZE);
    ephKey.pubSet = 1;
    
    // print_key_debug("Reconstructed ephemeral key", &ephKey);
    
    /* Use ORIGINAL WolfSSL shared secret computation */
    word32 sharedSecretSz = CURVE25519_KEYSIZE;
    // printf("    Computing: shared_secret = receiver_private * ephemeral_public\n");
    // start_timing();
    ret = wc_curve25519_shared_secret_ex(recvKey, &ephKey, sharedSecret, &sharedSecretSz, EC25519_LITTLE_ENDIAN);
    // end_timing("Software DH operation");
    
    wc_curve25519_free(&ephKey);
    
    if (ret != 0) {
        // printf("DH operation failed: %d\n", ret);
        return ret;
    }
    
    // print_hex_debug("DH shared secret", sharedSecret, CURVE25519_KEYSIZE);
    
    /* Step 2: Extract and Expand */
    // printf("Step 2: Extract and Expand\n");
    XMEMCPY(kemContext, ephemeralPubKey, CURVE25519_KEYSIZE);
    XMEMCPY(kemContext + CURVE25519_KEYSIZE, recvKey->p.point, CURVE25519_KEYSIZE);
    
    // print_hex_debug("KEM context", kemContext, sizeof(kemContext));
    
    byte extractedSecret[CURVE25519_KEYSIZE];
    ret = sw_HpkeExtractAndExpand(hpke, sharedSecret, sizeof(sharedSecret),
                                  kemContext, sizeof(kemContext),
                                  extractedSecret);
    if (ret != 0) {
        // printf("Extract and Expand failed: %d\n", ret);
        return ret;
    }
    
    /* Step 3: Key Schedule */
    // printf("Step 3: Key Schedule\n");
    ret = sw_HpkeKeyScheduleBase(hpke, extractedSecret, info, infoSz, key, baseNonce);
    if (ret != 0) {
        // printf("Key Schedule failed: %d\n", ret);
        return ret;
    }
    
    // printf("=== Setup Base Receiver completed successfully ===\n");
    return 0;
}

/* Software HPKE Seal Base */
static int sw_HpkeSealBase(Hpke* hpke, void* ephemeralKey, void* receiverKey,
                           const byte* info, word32 infoSz,
                           const byte* aad, word32 aadSz,
                           const byte* plaintext, word32 plaintextSz,
                           byte* ciphertext)
{
    int ret;
    byte key[16];
    byte baseNonce[12];
    byte nonce[12];
    byte authTag[16];
    Aes aes;
    
    // printf("\n=== HPKE Seal Base (Software Implementation) DEBUG ===\n");
    
    // /* Debug: Print inputs */
    // printf("Input parameters:\n");
    // print_hex_debug("Info", info, infoSz);
    // print_hex_debug("AAD", aad, aadSz);
    // print_hex_debug("Plaintext", plaintext, plaintextSz);
    
    if (hpke == NULL || ephemeralKey == NULL || receiverKey == NULL || 
        plaintext == NULL || ciphertext == NULL) {
        // printf("Invalid parameters\n");
        return BAD_FUNC_ARG;
    }
    
    if (hpke->kem != DHKEM_X25519_HKDF_SHA256) {
        // printf("Unsupported KEM: 0x%04x\n", hpke->kem);
        return BAD_FUNC_ARG;
    }
    
    /* Setup sender context */
    ret = sw_HpkeSetupBaseSender(hpke, ephemeralKey, receiverKey, info, infoSz, key, baseNonce);
    if (ret != 0) {
        // printf("Setup Base Sender failed: %d\n", ret);
        return ret;
    }
    
    /* Debug: Print derived keys */
    // print_hex_debug("Derived AES key", key, 16);
    // print_hex_debug("Derived base nonce", baseNonce, 12);
    
    /* Create nonce (base_nonce XOR sequence number, sequence = 0 for base mode) */
    XMEMCPY(nonce, baseNonce, 12);
    // print_hex_debug("Final nonce", nonce, 12);
    
    /* AES-GCM encryption */
    // printf("AES-GCM Encryption\n");
    // start_timing();
    
    ret = wc_AesInit(&aes, hpke->heap, INVALID_DEVID);
    if (ret != 0) {
        // printf("AES init failed: %d\n", ret);
        return ret;
    }
    
    ret = wc_AesGcmSetKey(&aes, key, 16);
    if (ret != 0) {
        // printf("AES set key failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }
    
    ret = wc_AesGcmEncrypt(&aes, ciphertext, plaintext, plaintextSz,
                           nonce, sizeof(nonce), authTag, sizeof(authTag),
                           aad, aadSz);
    
    wc_AesFree(&aes);
    // end_timing("AES-GCM Encryption");
    
    if (ret != 0) {
        // printf("AES-GCM encryption failed: %d\n", ret);
        return ret;
    }
    
    /* Debug: Print encryption results */
    // print_hex_debug("Ciphertext", ciphertext, plaintextSz);
    // print_hex_debug("Auth tag", authTag, sizeof(authTag));
    
    /* Append auth tag */
    XMEMCPY(ciphertext + plaintextSz, authTag, sizeof(authTag));
    
    // print_hex_debug("Final ciphertext + tag", ciphertext, plaintextSz + sizeof(authTag));
    // printf("=== HPKE Seal Base Completed Successfully ===\n");
    return 0;
}


/* Static buffers for HPKE large data test (following AES-GCM pattern) */
#define HPKE_SW_TEST_BYTES (1 * 1024)  // 1KB test size

/* Static buffers for large self-test (avoid libc malloc/free on baremetal) */
static byte hpke_sw_plaintext_buf[HPKE_SW_TEST_BYTES];      // 1KB
static byte hpke_sw_aad_buf[32];                            // 32 bytes AAD
static byte hpke_sw_ciphertext_buf[HPKE_SW_TEST_BYTES + 16]; // 1KB + 16-byte tag
static byte hpke_sw_decrypted_buf[HPKE_SW_TEST_BYTES];      // 1KB


/* Modified sw_HpkeOpenBase with debug output */
static int sw_HpkeOpenBase(Hpke* hpke, void* receiverKey, 
                           const byte* ephemeralPubKey, word16 ephemeralPubKeySz,
                           const byte* info, word32 infoSz,
                           const byte* aad, word32 aadSz,
                           const byte* ciphertext, word32 ciphertextSz,
                           byte* plaintext)
{
    int ret;
    byte key[16];
    byte baseNonce[12];
    byte nonce[12];
    byte authTag[16];
    Aes aes;
    word32 plaintextSz;
    
    // printf("\n=== HPKE Open Base (Software Implementation) DEBUG ===\n");
    
    // /* Debug: Print inputs */
    // printf("Input parameters:\n");
    // print_hex_debug("Ephemeral public key", ephemeralPubKey, ephemeralPubKeySz);
    // print_hex_debug("Info", info, infoSz);
    // print_hex_debug("AAD", aad, aadSz);
    // print_hex_debug("Ciphertext + tag", ciphertext, ciphertextSz);
    
    if (hpke == NULL || receiverKey == NULL || ephemeralPubKey == NULL ||
        ciphertext == NULL || plaintext == NULL) {
        // printf("Invalid parameters\n");
        return BAD_FUNC_ARG;
    }
    
    if (hpke->kem != DHKEM_X25519_HKDF_SHA256) {
        // printf("Unsupported KEM: 0x%04x\n", hpke->kem);
        return BAD_FUNC_ARG;
    }
    
    if (ciphertextSz < 16) {
        // printf("Ciphertext too small: %u bytes\n", ciphertextSz);
        return BAD_FUNC_ARG;
    }
    
    plaintextSz = ciphertextSz - 16;
    
    /* Extract auth tag */
    XMEMCPY(authTag, ciphertext + plaintextSz, sizeof(authTag));
    // print_hex_debug("Extracted auth tag", authTag, sizeof(authTag));
    // print_hex_debug("Ciphertext only", ciphertext, plaintextSz);
    
    /* Setup receiver context */
    ret = sw_HpkeSetupBaseReceiver(hpke, receiverKey, ephemeralPubKey, ephemeralPubKeySz,
                                   info, infoSz, key, baseNonce);
    if (ret != 0) {
        // printf("Setup Base Receiver failed: %d\n", ret);
        return ret;
    }
    
    /* Debug: Print derived keys */
    // print_hex_debug("Derived AES key", key, 16);
    // print_hex_debug("Derived base nonce", baseNonce, 12);
    
    /* Create nonce (base_nonce XOR sequence number, sequence = 0 for base mode) */
    XMEMCPY(nonce, baseNonce, 12);
    // print_hex_debug("Final nonce", nonce, 12);
    
    /* AES-GCM decryption */
    // printf("AES-GCM Decryption\n");
    // start_timing();
    
    ret = wc_AesInit(&aes, hpke->heap, INVALID_DEVID);
    if (ret != 0) {
        // printf("AES init failed: %d\n", ret);
        return ret;
    }
    
    ret = wc_AesGcmSetKey(&aes, key, 16);
    if (ret != 0) {
        // printf("AES set key failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }
    
    ret = wc_AesGcmDecrypt(&aes, plaintext, ciphertext, plaintextSz,
                           nonce, sizeof(nonce), authTag, sizeof(authTag),
                           aad, aadSz);
    
    wc_AesFree(&aes);
    // end_timing("AES-GCM Decryption");
    
    if (ret != 0) {
        // printf("AES-GCM decryption failed: %d\n", ret);
        return ret;
    }
    
    /* Debug: Print decryption result */
    // print_hex_debug("Decrypted plaintext", plaintext, plaintextSz);
    
    // printf("=== HPKE Open Base Completed Successfully ===\n");
    return 0;
}

/* Modified test function with 1KB static buffers */
static int test_hpke_pure_software(void)
{
    printf("\n=== HPKE Pure Software Implementation Test (1KB Data) ===\n");
    
    int ret = 0;
    Hpke hpke;
    WC_RNG rng;
    void* receiverKey = NULL;
    void* ephemeralKey = NULL;
    
    /* Use 1KB plaintext with static allocation */
    const word32 plaintext_len = HPKE_SW_TEST_BYTES;  // 1KB
    const word32 aad_len = 32;                        // 32 bytes AAD
    const char* info_str = "Large software test";
    word32 info_len = strlen(info_str);
    
    /* Use static buffers - NO malloc() calls */
    byte* plaintext = hpke_sw_plaintext_buf;
    byte* aad = hpke_sw_aad_buf;
    byte* ciphertext = hpke_sw_ciphertext_buf;
    byte* decrypted = hpke_sw_decrypted_buf;
    
    printf("Using static buffers: %u-byte plaintext, %u-byte AAD\n", 
           plaintext_len, aad_len);
    
    /* Fill with test data pattern */
    printf("Filling test data...\n");
    for (word32 i = 0; i < plaintext_len; i++) {
        plaintext[i] = (byte)(i & 0xFF);
    }
    for (word32 i = 0; i < aad_len; i++) {
        aad[i] = (byte)((i + 0x55) & 0xFF);
    }
    
    /* Print a sample of the test data */
    printf("Test data preview:\n");
    print_hex_debug("Plaintext (first 32 bytes)", plaintext, 32);
    print_hex_debug("AAD", aad, aad_len);
    print_hex_debug("Info", (const byte*)info_str, info_len);
    
    /* Initialize RNG */
    printf("Initializing RNG...\n");
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    if (ret != 0) {
        printf("RNG init failed: %d\n", ret);
        return ret;
    }
    
    /* Initialize HPKE */
    printf("Initializing HPKE...\n");
    ret = wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, HPKE_AES_128_GCM, g_heap_hint);
    if (ret != 0) {
        printf("HPKE init failed: %d\n", ret);
        wc_FreeRng(&rng);
        return ret;
    }
    
    /* Generate keys using ORIGINAL WolfSSL functions with DEBUG */
    printf("\n=== STEP 1: RECEIVER KEY GENERATION ===\n");
    start_timing();
    ret = wc_HpkeGenerateKeyPair(&hpke, &receiverKey, &rng);  // ← ORIGINAL SOFTWARE
    end_timing("Receiver key generation (wc_HpkeGenerateKeyPair)");
    if (ret != 0) {
        printf("Receiver key generation failed: %d\n", ret);
        goto cleanup;
    }
    
    /* Debug: Print generated receiver key */
    print_key_debug("Generated Receiver Key", (curve25519_key*)receiverKey);

    printf("\n=== STEP 2: EPHEMERAL KEY GENERATION ===\n");
    start_timing();
    ret = wc_HpkeGenerateKeyPair(&hpke, &ephemeralKey, &rng); // ← ORIGINAL SOFTWARE
    end_timing("Ephemeral key generation (wc_HpkeGenerateKeyPair)");
    if (ret != 0) {
        printf("Ephemeral key generation failed: %d\n", ret);
        goto cleanup;
    }
    
    /* Debug: Print generated ephemeral key */
    print_key_debug("Generated Ephemeral Key", (curve25519_key*)ephemeralKey);
    
    /* Get ephemeral public key */
    printf("Serializing ephemeral public key...\n");
    byte ephemeral_pk[32];
    word16 ephemeral_pk_size = sizeof(ephemeral_pk);
    ret = wc_HpkeSerializePublicKey(&hpke, ephemeralKey, ephemeral_pk, &ephemeral_pk_size);
    if (ret != 0) {
        printf("Public key serialization failed: %d\n", ret);
        goto cleanup;
    }
    print_hex_debug("Serialized ephemeral public key", ephemeral_pk, ephemeral_pk_size);
    
    /* Seal */
    printf("\n=== STEP 3: SEAL OPERATION (1KB DATA) ===\n");
    printf("Sealing %u bytes of plaintext with %u bytes of AAD...\n", plaintext_len, aad_len);
    start_timing();
    ret = sw_HpkeSealBase(&hpke, ephemeralKey, receiverKey,
                          (const byte*)info_str, info_len,
                          aad, aad_len,
                          plaintext, plaintext_len,
                          ciphertext);
    end_timing("1KB software seal operation");
    
    if (ret != 0) {
        printf("Seal failed: %d\n", ret);
        goto cleanup;
    }
    
    /* Print a sample of the encrypted result */
    printf("Encryption results preview:\n");
    print_hex_debug("Ciphertext (first 32 bytes)", ciphertext, 32);
    print_hex_debug("Auth tag (last 16 bytes)", ciphertext + plaintext_len, 16);
    
    /* Open */
    printf("\n=== STEP 4: OPEN OPERATION (1KB DATA) ===\n");
    printf("Opening %u bytes of ciphertext...\n", plaintext_len + 16);
    start_timing();
    ret = sw_HpkeOpenBase(&hpke, receiverKey, ephemeral_pk, ephemeral_pk_size,
                          (const byte*)info_str, info_len,
                          aad, aad_len,
                          ciphertext, plaintext_len + 16,
                          decrypted);
    end_timing("1KB software open operation");
    
    if (ret != 0) {
        printf("Open failed: %d\n", ret);
        goto cleanup;
    }
    
    /* Print a sample of the decrypted result */
    printf("Decryption results preview:\n");
    print_hex_debug("Decrypted plaintext (first 32 bytes)", decrypted, 32);
    
    /* Verify */
    printf("\n=== VERIFICATION (1KB DATA) ===\n");
    printf("Verifying %u bytes of data...\n", plaintext_len);
    
    if (XMEMCMP(plaintext, decrypted, plaintext_len) == 0) {
        printf("SUCCESS: 1KB pure software HPKE round-trip completed!\n");
        printf("✅ Software implementation working correctly!\n");
        printf("✅ Processed %u bytes plaintext + %u bytes AAD\n", plaintext_len, aad_len);
        printf("✅ All %u bytes verified successfully\n", plaintext_len);
    } else {
        printf("FAIL: Decrypted data doesn't match\n");
        
        /* Find first mismatch for debugging */
        for (word32 i = 0; i < plaintext_len; i++) {
            if (plaintext[i] != decrypted[i]) {
                printf("First mismatch at byte %u: original=0x%02x decrypted=0x%02x\n", 
                       i, plaintext[i], decrypted[i]);
                break;
            }
        }
        ret = -1;
    }
    
cleanup:
    if (receiverKey != NULL) {
        wc_HpkeFreeKey(&hpke, hpke.kem, receiverKey, hpke.heap);
    }
    if (ephemeralKey != NULL) {
        wc_HpkeFreeKey(&hpke, hpke.kem, ephemeralKey, hpke.heap);
    }
    wc_FreeRng(&rng);
    
    return ret;
}

/* Main function */
int main(void)
{
    printf("HPKE Pure Software Implementation Test\n");
    printf("=====================================\n");
    printf("Using original WolfSSL functions for performance comparison\n\n");
    
    unsigned long main_start = rdcycle();
    
    /* Setup */
    if (setup_wolfssl_memory() != 0) {
        printf("FAIL: Static memory setup failed\n");
        return -1;
    }
    
    /* Test */
    int result = test_hpke_pure_software();
    
    unsigned long main_end = rdcycle();
    
    printf("\n=====================================\n");
    printf("Performance Summary:\n");
    printf("  Total time: %lu cycles\n", main_end - main_start);
    printf("  Software operations: %lu cycles\n", total_cycles);
    
    if (result == 0) {
        printf("\nPURE SOFTWARE HPKE TEST PASSED!\n");
        printf("Software implementation working correctly!\n");
    } else {
        printf("\nPURE SOFTWARE HPKE TEST FAILED!\n");
    }
    
    return result;
}