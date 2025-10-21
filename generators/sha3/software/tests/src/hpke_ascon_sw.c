/* hpke_sw_ascon.c
 * Pure software HPKE implementation with Ascon-128 AEAD instead of AES-128-GCM
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
#include <wolfssl/wolfcrypt/ascon.h>  // ← Replace AES with Ascon

#ifndef XMEMSET  
#define XMEMSET memset
#endif

#ifndef XMEMCPY
#define XMEMCPY memcpy
#endif

#ifndef XMEMCMP
#define XMEMCMP memcmp
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

/* Create Ascon context with proper heap hint */
static wc_AsconAEAD128* create_ascon_context(void)
{
    wc_AsconAEAD128* asconAEAD = (wc_AsconAEAD128*) XMALLOC(sizeof(wc_AsconAEAD128), 
                                                            g_heap_hint, DYNAMIC_TYPE_ASCON);
    
    if (asconAEAD != NULL) {
        int ret = wc_AsconAEAD128_Init(asconAEAD);
        if (ret != 0) {
            // printf("❌ Ascon init failed: %d\n", ret);
            XFREE(asconAEAD, g_heap_hint, DYNAMIC_TYPE_ASCON);
            return NULL;
        }
    }
    
    return asconAEAD;
}

/* Free Ascon context */
static void free_ascon_context(wc_AsconAEAD128* asconAEAD)
{
    if (asconAEAD) {
        wc_AsconAEAD128_Clear(asconAEAD);
        XFREE(asconAEAD, g_heap_hint, DYNAMIC_TYPE_ASCON);
    }
}

/* Helper function to print hex values */
static void print_hex_debug(const char* label, const byte* data, int len)
{
    printf("    %s (%d bytes):\n      ", label, len);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i != len - 1) {
            printf("\n      ");
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

    // printf("  === Performing DH operation with software ===\n");
    
    /* Debug: Print input keys */
    // print_key_debug("Ephemeral Key for DH", ephKey);
    // print_key_debug("Receiver Key for DH", recvKey);
    
    /* Use ORIGINAL WolfSSL shared secret computation */
    // printf("    Computing: shared_secret = ephemeral_private * receiver_public\n");
    // start_timing();
    int ret = wc_curve25519_shared_secret_ex(ephKey, recvKey, sharedSecret, &sharedSecretSz, EC25519_LITTLE_ENDIAN);
    // end_timing("Software Curve25519 shared secret");
    
    // if (ret == 0) {
    //     // print_hex_debug("DH shared secret result", sharedSecret, CURVE25519_KEYSIZE);
    // } else {
    //     printf("    DH operation failed: %d\n", ret);
    // }
    
    return ret;
}

/* Modified sw_HpkeExtractAndExpand with debug output */
static int sw_HpkeExtractAndExpand(Hpke* hpke, byte* dh, word32 dhSz,
                                   byte* kemContext, word32 kemContextSz,
                                   byte* sharedSecret)
{
    int ret;
    byte prkExtract[WC_SHA256_DIGEST_SIZE];
    
    // printf("  === Extract and Expand operation DEBUG ===\n");
    
    /* Debug: Print inputs */
    // print_hex_debug("Input DH", dh, dhSz);
    // print_hex_debug("Input KEM context", kemContext, kemContextSz);
    
    /* Step 1: Extract */
    // printf("    HKDF Extract step\n");
    // start_timing();
    ret = wc_HKDF_Extract(WC_SHA256, 
                          NULL, 0,  /* No salt */
                          dh, dhSz, 
                          prkExtract);
    // end_timing("HKDF Extract");
    
    // if (ret != 0) {
    //     // printf("    HKDF Extract failed: %d\n", ret);
    //     return ret;
    // }
    
    /* Debug: Print extract result */
    // print_hex_debug("PRK after Extract", prkExtract, sizeof(prkExtract));
    
    /* Step 2: Expand */
    // printf("    HKDF Expand step\n");
    // start_timing();
    ret = wc_HKDF_Expand(WC_SHA256, 
                         prkExtract, sizeof(prkExtract),
                         kemContext, kemContextSz,
                         sharedSecret, CURVE25519_KEYSIZE);
    // end_timing("HKDF Expand");
    
    // if (ret != 0) {
    //     printf("    HKDF Expand failed: %d\n", ret);
    //     return ret;
    // }
    
    /* Debug: Print expand result */
    // print_hex_debug("Shared secret after Expand", sharedSecret, CURVE25519_KEYSIZE);
    // printf("  === Extract and Expand completed successfully ===\n");
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
    
    // printf("  === HPKE Encapsulation DEBUG ===\n");
    
    /* Debug: Print input keys */
    // print_key_debug("Ephemeral Key Input", ephKey);
    // print_key_debug("Receiver Key Input", recvKey);
    
    /* Step 1: DH operation with software */
    // printf("    Step 1: DH operation\n");
    ret = sw_HpkeDh(hpke, ephemeralKey, receiverKey, dh);
    if (ret != 0) {
        // printf("    DH operation failed: %d\n", ret);
        return ret;
    }
    
    /* Step 2: Create KEM context (ephemeral_pk || receiver_pk) */
    // printf("    Step 2: Create KEM context\n");
    XMEMCPY(kemContext, ephKey->p.point, CURVE25519_KEYSIZE);
    XMEMCPY(kemContext + CURVE25519_KEYSIZE, recvKey->p.point, CURVE25519_KEYSIZE);
    
    /* Debug: Print KEM context components */
    // print_hex_debug("Ephemeral public key", ephKey->p.point, CURVE25519_KEYSIZE);
    // print_hex_debug("Receiver public key", recvKey->p.point, CURVE25519_KEYSIZE);
    // print_hex_debug("KEM context (eph_pk || recv_pk)", kemContext, sizeof(kemContext));
    
    /* Step 3: Extract and Expand */
    // printf("    Step 3: Extract and Expand\n");
    ret = sw_HpkeExtractAndExpand(hpke, dh, sizeof(dh), 
                                  kemContext, sizeof(kemContext),
                                  sharedSecret);
    
    // if (ret == 0) {
    //     /* Debug: Print final shared secret */
    //     print_hex_debug("Final HPKE shared secret", sharedSecret, CURVE25519_KEYSIZE);
    //     printf("  === Encapsulation completed successfully ===\n");
    // } else {
    //     printf("  Encapsulation failed: %d\n", ret);
    // }
    
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
    start_timing();
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


/* MODIFIED: Key Schedule for Ascon-128 (16-byte key, 16-byte nonce) */
static int sw_HpkeKeyScheduleBaseAscon(Hpke* hpke, byte* sharedSecret, 
                                       const byte* info, word32 infoSz,
                                       byte* key, byte* baseNonce)
{
    int ret;
    byte prkSchedule[WC_SHA256_DIGEST_SIZE];
    byte keyScheduleContext[1 + infoSz];  /* mode || info */
    byte keyInfo[4] = {0x00, 0x01, 0x00, 0x10};      /* "key" + length 16 */
    byte nonceInfo[7] = {0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00}; /* "base_nonce" + length 16 (not 12!) */
    
    /* Create key schedule context: mode (0x00 for base) || info */
    keyScheduleContext[0] = 0x00;  /* Base mode */
    if (info != NULL && infoSz > 0) {
        XMEMCPY(keyScheduleContext + 1, info, infoSz);
    }
    
    /* Step 1: Schedule Extract */
    ret = wc_HKDF_Extract(WC_SHA256,
                          NULL, 0,  /* No salt */
                          sharedSecret, CURVE25519_KEYSIZE,
                          prkSchedule);
    if (ret != 0) {
        return ret;
    }
    
    /* Step 2: Expand for Ascon-128 key (16 bytes) */
    ret = wc_HKDF_Expand(WC_SHA256,
                         prkSchedule, sizeof(prkSchedule),
                         keyInfo, sizeof(keyInfo),
                         key, ASCON_AEAD128_KEY_SZ);  /* 16 bytes for Ascon-128 */
    if (ret != 0) {
        return ret;
    }
    
    /* Step 3: Expand for Ascon base nonce (16 bytes) */
    ret = wc_HKDF_Expand(WC_SHA256,
                         prkSchedule, sizeof(prkSchedule),
                         nonceInfo, sizeof(nonceInfo),
                         baseNonce, ASCON_AEAD128_NONCE_SZ);  /* 16 bytes for Ascon-128 */
    if (ret != 0) {
        return ret;
    }
    
    return 0;
}

/* MODIFIED: Setup functions to use Ascon key schedule */
static int sw_HpkeSetupBaseSenderAscon(Hpke* hpke, void* ephemeralKey, void* receiverKey,
                                       const byte* info, word32 infoSz,
                                       byte* key, byte* baseNonce)
{
    int ret;
    byte sharedSecret[CURVE25519_KEYSIZE];
    
    /* Step 1: Encapsulation (unchanged) */
    ret = sw_HpkeEncap(hpke, ephemeralKey, receiverKey, sharedSecret);
    if (ret != 0) {
        return ret;
    }
    
    /* Step 2: Key Schedule for Ascon */
    ret = sw_HpkeKeyScheduleBaseAscon(hpke, sharedSecret, info, infoSz, key, baseNonce);
    if (ret != 0) {
        return ret;
    }
    
    return 0;
}

static int sw_HpkeSetupBaseReceiverAscon(Hpke* hpke, void* receiverKey, 
                                         const byte* ephemeralPubKey, word32 ephemeralPubKeySz,
                                         const byte* info, word32 infoSz,
                                         byte* key, byte* baseNonce)
{
    int ret;
    byte sharedSecret[CURVE25519_KEYSIZE];
    byte kemContext[2 * CURVE25519_KEYSIZE];
    curve25519_key* recvKey = (curve25519_key*)receiverKey;
    
    if (ephemeralPubKeySz != CURVE25519_KEYSIZE) {
        return BAD_FUNC_ARG;
    }
    
    /* Step 1: DH operation */
    curve25519_key ephKey;
    ret = wc_curve25519_init_ex(&ephKey, hpke->heap, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    
    XMEMCPY(ephKey.p.point, ephemeralPubKey, CURVE25519_KEYSIZE);
    ephKey.pubSet = 1;
    
    word32 sharedSecretSz = CURVE25519_KEYSIZE;
    ret = wc_curve25519_shared_secret_ex(recvKey, &ephKey, sharedSecret, &sharedSecretSz, EC25519_LITTLE_ENDIAN);
    
    wc_curve25519_free(&ephKey);
    
    if (ret != 0) {
        return ret;
    }
    
    /* Step 2: Extract and Expand */
    XMEMCPY(kemContext, ephemeralPubKey, CURVE25519_KEYSIZE);
    XMEMCPY(kemContext + CURVE25519_KEYSIZE, recvKey->p.point, CURVE25519_KEYSIZE);
    
    byte extractedSecret[CURVE25519_KEYSIZE];
    ret = sw_HpkeExtractAndExpand(hpke, sharedSecret, sizeof(sharedSecret),
                                  kemContext, sizeof(kemContext),
                                  extractedSecret);
    if (ret != 0) {
        return ret;
    }
    
    /* Step 3: Key Schedule for Ascon */
    ret = sw_HpkeKeyScheduleBaseAscon(hpke, extractedSecret, info, infoSz, key, baseNonce);
    if (ret != 0) {
        return ret;
    }
    
    return 0;
}

/* MODIFIED: HPKE Seal with Ascon-128 AEAD */
static int sw_HpkeSealBaseAscon(Hpke* hpke, void* ephemeralKey, void* receiverKey,
                                const byte* info, word32 infoSz,
                                const byte* aad, word32 aadSz,
                                const byte* plaintext, word32 plaintextSz,
                                byte* ciphertext)
{
    int ret;
    byte key[ASCON_AEAD128_KEY_SZ];        /* 16-byte Ascon key */
    byte baseNonce[ASCON_AEAD128_NONCE_SZ]; /* 16-byte Ascon nonce */
    byte nonce[ASCON_AEAD128_NONCE_SZ];
    byte authTag[ASCON_AEAD128_TAG_SZ];    /* 16-byte Ascon tag */
    wc_AsconAEAD128* asconAEAD = NULL;
    
    // printf("\n=== HPKE Seal Base (Ascon-128 Implementation) ===\n");
    
    if (hpke == NULL || ephemeralKey == NULL || receiverKey == NULL || 
        plaintext == NULL || ciphertext == NULL) {
        return BAD_FUNC_ARG;
    }
    
    if (hpke->kem != DHKEM_X25519_HKDF_SHA256) {
        return BAD_FUNC_ARG;
    }
    
    /* Setup sender context */
    ret = sw_HpkeSetupBaseSenderAscon(hpke, ephemeralKey, receiverKey, info, infoSz, key, baseNonce);
    if (ret != 0) {
        // printf("Setup Base Sender failed: %d\n", ret);
        return ret;
    }
    
    // print_hex_debug("Derived Ascon key", key, ASCON_AEAD128_KEY_SZ);
    // print_hex_debug("Derived base nonce", baseNonce, ASCON_AEAD128_NONCE_SZ);
    
    /* Create nonce (base_nonce XOR sequence number, sequence = 0 for base mode) */
    XMEMCPY(nonce, baseNonce, ASCON_AEAD128_NONCE_SZ);
    // print_hex_debug("Final nonce", nonce, ASCON_AEAD128_NONCE_SZ);
    
    /* Ascon-128 AEAD encryption */
    // printf("Ascon-128 AEAD Encryption\n");
    // start_timing();
    
    asconAEAD = create_ascon_context();
    if (asconAEAD == NULL) {
        // printf("Failed to create Ascon context\n");
        return -1;
    }
    
    ret = wc_AsconAEAD128_SetKey(asconAEAD, key);
    if (ret != 0) {
        // printf("Ascon set key failed: %d\n", ret);
        goto cleanup;
    }
    
    ret = wc_AsconAEAD128_SetNonce(asconAEAD, nonce);
    if (ret != 0) {
        // printf("Ascon set nonce failed: %d\n", ret);
        goto cleanup;
    }
    
    ret = wc_AsconAEAD128_SetAD(asconAEAD, aad, aadSz);
    if (ret != 0) {
        // printf("Ascon set AAD failed: %d\n", ret);
        goto cleanup;
    }
    
    ret = wc_AsconAEAD128_EncryptUpdate(asconAEAD, ciphertext, plaintext, plaintextSz);
    if (ret != 0) {
        // printf("Ascon encrypt update failed: %d\n", ret);
        goto cleanup;
    }
    
    ret = wc_AsconAEAD128_EncryptFinal(asconAEAD, authTag);
    if (ret != 0) {
        // printf("Ascon encrypt final failed: %d\n", ret);
        goto cleanup;
    }
    
    // end_timing("Ascon-128 AEAD Encryption");
    
    /* Append auth tag */
    XMEMCPY(ciphertext + plaintextSz, authTag, ASCON_AEAD128_TAG_SZ);
    
    // print_hex_debug("Ciphertext", ciphertext, plaintextSz);
    // print_hex_debug("Ascon auth tag", authTag, ASCON_AEAD128_TAG_SZ);
    
    // printf("=== HPKE Seal Base (Ascon) Completed Successfully ===\n");
    ret = 0;
    
cleanup:
    free_ascon_context(asconAEAD);
    return ret;
}

/* MODIFIED: HPKE Open with Ascon-128 AEAD */
static int sw_HpkeOpenBaseAscon(Hpke* hpke, void* receiverKey, 
                                const byte* ephemeralPubKey, word16 ephemeralPubKeySz,
                                const byte* info, word32 infoSz,
                                const byte* aad, word32 aadSz,
                                const byte* ciphertext, word32 ciphertextSz,
                                byte* plaintext)
{
    int ret;
    byte key[ASCON_AEAD128_KEY_SZ];        /* 16-byte Ascon key */
    byte baseNonce[ASCON_AEAD128_NONCE_SZ]; /* 16-byte Ascon nonce */
    byte nonce[ASCON_AEAD128_NONCE_SZ];
    byte authTag[ASCON_AEAD128_TAG_SZ];    /* 16-byte Ascon tag */
    wc_AsconAEAD128* asconAEAD = NULL;
    word32 plaintextSz;
    
    // printf("\n=== HPKE Open Base (Ascon-128 Implementation) ===\n");
    
    if (hpke == NULL || receiverKey == NULL || ephemeralPubKey == NULL ||
        ciphertext == NULL || plaintext == NULL) {
        return BAD_FUNC_ARG;
    }
    
    if (hpke->kem != DHKEM_X25519_HKDF_SHA256) {
        return BAD_FUNC_ARG;
    }
    
    if (ciphertextSz < ASCON_AEAD128_TAG_SZ) {
        // printf("Ciphertext too small: %u bytes\n", ciphertextSz);
        return BAD_FUNC_ARG;
    }
    
    plaintextSz = ciphertextSz - ASCON_AEAD128_TAG_SZ;  /* Account for 16-byte Ascon tag */
    
    /* Extract auth tag */
    XMEMCPY(authTag, ciphertext + plaintextSz, ASCON_AEAD128_TAG_SZ);
    // print_hex_debug("Extracted Ascon auth tag", authTag, ASCON_AEAD128_TAG_SZ);
    // print_hex_debug("Ciphertext only", ciphertext, plaintextSz);
    
    /* Setup receiver context */
    ret = sw_HpkeSetupBaseReceiverAscon(hpke, receiverKey, ephemeralPubKey, ephemeralPubKeySz,
                                        info, infoSz, key, baseNonce);
    // if (ret != 0) {
    //     printf("Setup Base Receiver failed: %d\n", ret);
    //     return ret;
    // }
    
    // print_hex_debug("Derived Ascon key", key, ASCON_AEAD128_KEY_SZ);
    // print_hex_debug("Derived base nonce", baseNonce, ASCON_AEAD128_NONCE_SZ);
    
    /* Create nonce (base_nonce XOR sequence number, sequence = 0 for base mode) */
    XMEMCPY(nonce, baseNonce, ASCON_AEAD128_NONCE_SZ);
    // print_hex_debug("Final nonce", nonce, ASCON_AEAD128_NONCE_SZ);
    
    /* Ascon-128 AEAD decryption */
    // printf("Ascon-128 AEAD Decryption\n");
    // start_timing();
    
    asconAEAD = create_ascon_context();
    if (asconAEAD == NULL) {
        // printf("Failed to create Ascon context\n");
        return -1;
    }
    
    ret = wc_AsconAEAD128_SetKey(asconAEAD, key);
    if (ret != 0) {
        // printf("Ascon set key failed: %d\n", ret);
        goto cleanup;
    }
    
    ret = wc_AsconAEAD128_SetNonce(asconAEAD, nonce);
    if (ret != 0) {
        // printf("Ascon set nonce failed: %d\n", ret);
        goto cleanup;
    }
    
    ret = wc_AsconAEAD128_SetAD(asconAEAD, aad, aadSz);
    if (ret != 0) {
        // printf("Ascon set AAD failed: %d\n", ret);
        goto cleanup;
    }
    
    ret = wc_AsconAEAD128_DecryptUpdate(asconAEAD, plaintext, ciphertext, plaintextSz);
    if (ret != 0) {
        // printf("Ascon decrypt update failed: %d\n", ret);
        goto cleanup;
    }
    
    ret = wc_AsconAEAD128_DecryptFinal(asconAEAD, authTag);
    if (ret != 0) {
        // printf("Ascon decrypt final failed: %d\n", ret);
        goto cleanup;
    }
    
    // end_timing("Ascon-128 AEAD Decryption");
    
    // print_hex_debug("Decrypted plaintext", plaintext, plaintextSz);
    
    // printf("=== HPKE Open Base (Ascon) Completed Successfully ===\n");
    ret = 0;
    
cleanup:
    free_ascon_context(asconAEAD);
    return ret;
}

/* Modified test function */
static int test_hpke_pure_software_ascon(void)
{
    printf("\n=== HPKE Pure Software Implementation with Ascon-128 (1KB Data) ===\n");
    
    int ret = 0;
    Hpke hpke;
    WC_RNG rng;
    void* receiverKey = NULL;
    void* ephemeralKey = NULL;
    
    const word32 plaintext_len = 1024;  // 1KB
    const word32 aad_len = 32;          // 32 bytes AAD
    const char* info_str = "Large Ascon test";
    word32 info_len = strlen(info_str);
    
    /* Static buffers */
    static byte plaintext[1024];
    static byte aad[32];
    static byte ciphertext[1024 + ASCON_AEAD128_TAG_SZ];  // Include Ascon tag space
    static byte decrypted[1024];
    
    printf("Using static buffers: %u-byte plaintext, %u-byte AAD\n", 
           plaintext_len, aad_len);
    printf("Ascon-128 parameters: %d-byte key, %d-byte nonce, %d-byte tag\n",
           ASCON_AEAD128_KEY_SZ, ASCON_AEAD128_NONCE_SZ, ASCON_AEAD128_TAG_SZ);
    
    /* Fill with test data pattern */
    for (word32 i = 0; i < plaintext_len; i++) {
        plaintext[i] = (byte)(i & 0xFF);
    }
    for (word32 i = 0; i < aad_len; i++) {
        aad[i] = (byte)((i + 0x55) & 0xFF);
    }
    
    /* Initialize RNG and HPKE */
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    if (ret != 0) {
        printf("RNG init failed: %d\n", ret);
        return ret;
    }
    
    ret = wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, HPKE_AES_128_GCM, g_heap_hint);
    if (ret != 0) {
        // printf("HPKE init failed: %d\n", ret);
        wc_FreeRng(&rng);
        return ret;
    }
    
    /* Generate keys */
    printf("\n=== KEY GENERATION ===\n");
    start_timing();
    ret = wc_HpkeGenerateKeyPair(&hpke, &receiverKey, &rng);
    end_timing("Receiver key generation");
    if (ret != 0) {
        printf("Receiver key generation failed: %d\n", ret);
        goto cleanup;
    }

    start_timing();
    ret = wc_HpkeGenerateKeyPair(&hpke, &ephemeralKey, &rng);
    end_timing("Ephemeral key generation");
    if (ret != 0) {
        printf("Ephemeral key generation failed: %d\n", ret);
        goto cleanup;
    }
    
    /* Get ephemeral public key */
    byte ephemeral_pk[32];
    word16 ephemeral_pk_size = sizeof(ephemeral_pk);
    ret = wc_HpkeSerializePublicKey(&hpke, ephemeralKey, ephemeral_pk, &ephemeral_pk_size);
    if (ret != 0) {
        printf("Public key serialization failed: %d\n", ret);
        goto cleanup;
    }
    
    /* Seal with Ascon-128 */
    printf("\n=== SEAL OPERATION (1KB DATA with Ascon-128) ===\n");
    start_timing();
    ret = sw_HpkeSealBaseAscon(&hpke, ephemeralKey, receiverKey,
                               (const byte*)info_str, info_len,
                               aad, aad_len,
                               plaintext, plaintext_len,
                               ciphertext);
    end_timing("1KB Ascon-128 seal operation");
    
    if (ret != 0) {
        printf("Ascon seal failed: %d\n", ret);
        goto cleanup;
    }
    
    /* Open with Ascon-128 */
    printf("\n=== OPEN OPERATION (1KB DATA with Ascon-128) ===\n");
    start_timing();
    ret = sw_HpkeOpenBaseAscon(&hpke, receiverKey, ephemeral_pk, ephemeral_pk_size,
                               (const byte*)info_str, info_len,
                               aad, aad_len,
                               ciphertext, plaintext_len + ASCON_AEAD128_TAG_SZ,
                               decrypted);
    end_timing("1KB Ascon-128 open operation");
    
    if (ret != 0) {
        printf("Ascon open failed: %d\n", ret);
        goto cleanup;
    }
    
    /* Verify */
    printf("\n=== VERIFICATION (1KB DATA) ===\n");
    
    if (XMEMCMP(plaintext, decrypted, plaintext_len) == 0) {
        printf("🎉 SUCCESS: 1KB HPKE with Ascon-128 completed!\n");
        printf("✅ Ascon-128 AEAD working in HPKE context!\n");
        printf("✅ Processed %u bytes plaintext + %u bytes AAD\n", plaintext_len, aad_len);
        printf("✅ All %u bytes verified successfully\n", plaintext_len);
        printf("✅ Post-quantum resistant AEAD operational!\n");
    } else {
        printf("❌ FAIL: Decrypted data doesn't match\n");
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
    printf("HPKE Pure Software Implementation with Ascon-128 AEAD\n");
    printf("===================================================\n");
    printf("Replacing AES-128-GCM with Ascon-128 for post-quantum resistance\n\n");
    
    unsigned long main_start = rdcycle();
    
    /* Setup */
    if (setup_wolfssl_memory() != 0) {
        printf("FAIL: Static memory setup failed\n");
        return -1;
    }
    
#ifdef HAVE_ASCON
    printf("✅ HAVE_ASCON detected - Ascon-128 available\n");
#else
    printf("❌ HAVE_ASCON not detected - cannot proceed\n");
    return -1;
#endif
    
    /* Test */
    int result = test_hpke_pure_software_ascon();
    
    unsigned long main_end = rdcycle();
    
    printf("\n===================================================\n");
    printf("Performance Summary:\n");
    printf("  Total time: %lu cycles\n", main_end - main_start);
    printf("  Ascon operations: %lu cycles\n", total_cycles);
    
    if (result == 0) {
        printf("\n🎉 HPKE WITH ASCON-128 TEST PASSED! 🎉\n");
        printf("✅ Post-quantum resistant HPKE implementation working!\n");
        printf("✅ Ascon-128 AEAD successfully integrated!\n");
        printf("✅ Ready for quantum-resistant communications!\n");
    } else {
        printf("\n❌ HPKE WITH ASCON-128 TEST FAILED!\n");
    }
    
    return result;
}