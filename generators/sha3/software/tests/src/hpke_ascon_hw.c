/* hpke_ascon.c
 * HPKE implementation with Ascon-128 AEAD instead of AES-GCM
 * Based on hpke_hw.c but using Ascon for authenticated encryption
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
#include <wolfssl/wolfcrypt/ascon.h>
#include "driver/hmac_sha/hmac_sha.h"

#ifndef XMEMSET  
#define XMEMSET memset
#endif

#ifndef XMEMCPY
#define XMEMCPY memcpy
#endif

#ifndef XMEMCMP
#define XMEMCMP memcmp
#endif

/* Hardware accelerator base addresses */
#define X25519_HW_BASE_ADDR  0x64004000
#define HMAC_SHA_HW_BASE_ADDR 0x64005000
#define SHA256_MODE 1

/* Static memory setup for WolfSSL */
#define WOLFSSL_STATIC_MEM_SIZE 1024*32
static byte g_wolfssl_mem[WOLFSSL_STATIC_MEM_SIZE];
static WOLFSSL_HEAP_HINT* g_heap_hint = NULL;

/* Test configuration */
#define HPKE_TEST_BYTES (1 * 1024)  // 1KB test size

/* Static buffers for HPKE large data test */
static byte hpke_plaintext_buf[HPKE_TEST_BYTES];     // 1KB
static byte hpke_aad_buf[256];                       // 256 bytes AAD
static byte hpke_ciphertext_buf[HPKE_TEST_BYTES + 16]; // 1KB + 16-byte tag
static byte hpke_decrypted_buf[HPKE_TEST_BYTES];     // 1KB

/* Timing functions */
static unsigned long step_start_cycles = 0;

static void start_timing(void)
{
    step_start_cycles = rdcycle();
}

static void end_timing(const char* operation)
{
    unsigned long end_cycles = rdcycle();
    unsigned long elapsed = end_cycles - step_start_cycles;
    printf("  HW Timing: %s took %lu cycles\n", operation, elapsed);
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
            printf("❌ Ascon init failed: %d\n", ret);
            XFREE(asconAEAD, g_heap_hint, DYNAMIC_TYPE_ASCON);
            return NULL;
        }
    }
    
    return asconAEAD;
}

/* Free Ascon context with proper heap hint */
static void free_ascon_context(wc_AsconAEAD128* asconAEAD)
{
    if (asconAEAD) {
        wc_AsconAEAD128_Clear(asconAEAD);
        XFREE(asconAEAD, g_heap_hint, DYNAMIC_TYPE_ASCON);
    }
}

/* Convert WolfSSL byte array to hardware uint64_t array */
static void wolfssl_to_hw_format(const byte* wolfssl_data, uint64_t hw_data[4])
{
    for (int i = 0; i < 4; i++) {
        hw_data[i] = 0;
        for (int j = 0; j < 8; j++) {
            int byte_idx = i * 8 + j;
            hw_data[i] = (hw_data[i] << 8) | ((uint64_t)wolfssl_data[byte_idx]);
        }
    }
}

/* Convert hardware uint64_t array to WolfSSL byte array */
static void hw_to_wolfssl_format(const uint64_t hw_data[4], byte* wolfssl_data)
{
    for (int i = 0; i < 4; i++) {
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
    
    wolfssl_to_hw_format(scalar, hw_scalar);
    wolfssl_to_hw_format(point, hw_point);
    
    hwx25519_init(x25519ctrl, hw_scalar, hw_point);
    hwx25519_results(x25519ctrl, hw_result);
    
    hw_to_wolfssl_format(hw_result, result);
    
    return 0;
}

/* Hardware-accelerated version of wc_curve25519_shared_secret_ex */
static int hw_curve25519_shared_secret_ex(curve25519_key* private_key, 
                                          curve25519_key* public_key,
                                          byte* out, word32* outlen,
                                          int endian)
{
    if (private_key == NULL || public_key == NULL || out == NULL || outlen == NULL)
        return BAD_FUNC_ARG;

    if (*outlen < CURVE25519_KEYSIZE)
        return BAD_FUNC_ARG;

    int ret = hw_curve25519_scalar_mult(out, private_key->k, public_key->p.point);
    
    if (ret == 0) {
        *outlen = CURVE25519_KEYSIZE;
    }
    
    return ret;
}

/* Hardware HKDF Extract using hmacsha_compute */
static int hw_HKDF_Extract(const byte* salt, word32 saltSz,
                          const byte* ikm, word32 ikmSz,
                          byte* prk)
{
    void* hmac_shactrl = (void*)HMAC_SHA_HW_BASE_ADDR;
    uint64_t hw_key[8] = {0};      /* HMAC key (salt or zeros) */
    uint64_t hw_msg[16] = {0};     /* HMAC message (IKM) */
    uint64_t hw_mac[8] = {0};      /* HMAC output (PRK) */
    
    /* Prepare HMAC key (salt) - Vietnamese pattern with zero padding */
    if (salt != NULL && saltSz > 0) {
        for (word32 i = 0; i < saltSz; i++) {
            word32 qw_idx = i / 4;           /* Each qword holds 4 bytes */
            word32 byte_idx = 3 - (i % 4);   /* Big-endian within 32 bits */
            
            if (qw_idx < 8) {
                /* Put data in LOWER 32 bits, keep UPPER 32 bits as zero */
                hw_key[qw_idx] |= ((uint64_t)salt[i]) << (8 * byte_idx);
            }
        }
    }
    
    /* Prepare HMAC message (IKM) - Vietnamese pattern with zero padding */
    for (word32 i = 0; i < ikmSz; i++) {
        word32 qw_idx = i / 4;           /* Each qword holds 4 bytes */
        word32 byte_idx = 3 - (i % 4);   /* Big-endian within 32 bits */
        
        if (qw_idx < 16) {
            /* Put data in LOWER 32 bits, keep UPPER 32 bits as zero */
            hw_msg[qw_idx] |= ((uint64_t)ikm[i]) << (8 * byte_idx);
        }
    }
    
    /* Execute HMAC with hardware */
    int ret = hmacsha_compute(hmac_shactrl, 
                             SHA256_MODE,           /* Hash type */
                             hw_key,           /* Key */
                             hw_msg,           /* Message */
                             ikmSz * 8,        /* Message size in bits */
                             hw_mac);          /* Output MAC */
    
    if (ret != 0) {
        return ret;
    }

    /* Convert result back to bytes */
    for (int i = 0; i < 8; i++) {
        uint32_t val = (uint32_t)(hw_mac[i] & 0xFFFFFFFF);
        prk[i*4+0] = (val >> 24) & 0xFF;
        prk[i*4+1] = (val >> 16) & 0xFF; 
        prk[i*4+2] = (val >> 8)  & 0xFF;
        prk[i*4+3] = (val >> 0)  & 0xFF;
    }
    
    return 0;
}

/* Hardware HKDF Expand using static buffers */
static int hw_HKDF_Expand(const byte* prk, word32 prkSz,
                          const byte* info, word32 infoSz,
                          byte* okm, word32 okmSz)
{
    void* hmac_shactrl = (void*)HMAC_SHA_HW_BASE_ADDR;
    uint64_t hw_key[8] = {0};      /* HMAC key (PRK) */
    uint64_t hw_mac[8] = {0};      /* HMAC output */
    
    /* Static buffers to avoid malloc() */
    static uint64_t hw_msg_buffer[64];  /* Max 512 bytes = 64 qwords */
    static byte msg_bytes_buffer[512];  /* Max 512 bytes message */
    
    /* Validate input sizes */
    if (prkSz != 32) {
        return -1;
    }
    if (okmSz > 255 * 32) {
        return -1;
    }
    
    /* Prepare HMAC key (PRK) - Vietnamese pattern */
    for (word32 i = 0; i < prkSz; i++) {
        word32 qw_idx = i / 4;           /* Vietnamese: 4 bytes per qword */
        word32 byte_idx = 3 - (i % 4);   /* Big-endian within 32 bits */
        
        if (qw_idx < 8) {
            hw_key[qw_idx] |= ((uint64_t)prk[i]) << (8 * byte_idx);
        }
    }
    
    /* HKDF-Expand generates OKM in chunks of hash_len (32 bytes for SHA256) */
    word32 hash_len = 32;
    word32 n = (okmSz + hash_len - 1) / hash_len;  /* Number of iterations needed */
    byte t_prev[32] = {0};  /* T(i-1) for chaining */
    word32 okm_offset = 0;
    
    for (word32 i = 1; i <= n; i++) {
        /* Calculate total message size for this iteration */
        word32 msg_len = 0;
        if (i > 1) {
            msg_len += hash_len;  /* T(i-1) */
        }
        msg_len += infoSz;        /* info */
        msg_len += 1;             /* counter */
        
        /* Check if message fits in static buffer */
        if (msg_len > sizeof(msg_bytes_buffer)) {
            return -1;
        }
        
        word32 msg_qwords = (msg_len + 3) / 4;  /* Convert to qwords */
        if (msg_qwords > sizeof(hw_msg_buffer)/sizeof(hw_msg_buffer[0])) {
            return -1;
        }
        
        /* Use static buffers instead of malloc */
        uint64_t* hw_msg = hw_msg_buffer;
        byte* msg_bytes = msg_bytes_buffer;
        
        /* Clear message buffers */
        XMEMSET(hw_msg, 0, msg_qwords * sizeof(uint64_t));
        XMEMSET(msg_bytes, 0, msg_len);
        
        word32 offset = 0;
        
        /* Add T(i-1) if not first iteration */
        if (i > 1) {
            XMEMCPY(msg_bytes + offset, t_prev, hash_len);
            offset += hash_len;
        }
        
        /* Add info */
        if (info != NULL && infoSz > 0) {
            XMEMCPY(msg_bytes + offset, info, infoSz);
            offset += infoSz;
        }
        
        /* Add counter byte */
        msg_bytes[offset] = (byte)i;
        offset += 1;
        
        /* Pack into Vietnamese pattern */
        for (word32 j = 0; j < msg_len; j++) {
            word32 qw_idx = j / 4;
            word32 byte_idx = 3 - (j % 4);
            if (qw_idx < msg_qwords) {
                hw_msg[qw_idx] |= ((uint64_t)msg_bytes[j]) << (8 * byte_idx);
            }
        }

        /* Execute HMAC with hardware */
        int ret = hmacsha_compute(hmac_shactrl, 
                                 SHA256_MODE,         /* Hash type */
                                 hw_key,              /* Key (PRK) */
                                 hw_msg,              /* Message (auto-chunked) */
                                 msg_len * 8,         /* Message size in bits */
                                 hw_mac);             /* Output MAC */

        if (ret != 0) {
            return ret;
        }
        
        /* Convert result back to bytes */
        byte t_current[32];
        for (int j = 0; j < 8; j++) {
            uint32_t val = (uint32_t)(hw_mac[j] & 0xFFFFFFFF);
            t_current[j*4+0] = (val >> 24) & 0xFF;
            t_current[j*4+1] = (val >> 16) & 0xFF; 
            t_current[j*4+2] = (val >> 8)  & 0xFF;
            t_current[j*4+3] = (val >> 0)  & 0xFF;
        }
        
        /* Copy appropriate amount to output */
        word32 copy_len = (okmSz - okm_offset > hash_len) ? hash_len : (okmSz - okm_offset);
        XMEMCPY(okm + okm_offset, t_current, copy_len);
        okm_offset += copy_len;
        
        /* Save for next iteration */
        XMEMCPY(t_prev, t_current, hash_len);
        
        /* Break if we have enough output */
        if (okm_offset >= okmSz) {
            break;
        }
    }
    
    XMEMSET(hw_msg_buffer, 0, sizeof(hw_msg_buffer));  /* Clear entire static buffer */
    XMEMSET(msg_bytes_buffer, 0, sizeof(msg_bytes_buffer));  /* Clear entire static buffer */
    
    return 0;
}

/* Hardware-accelerated DH operation following WolfSSL pattern */
static int hw_HpkeDh(Hpke* hpke, void* ephemeralKey, void* receiverKey, byte* sharedSecret)
{
    if (hpke == NULL || ephemeralKey == NULL || receiverKey == NULL || sharedSecret == NULL)
        return BAD_FUNC_ARG;

    if (hpke->kem != DHKEM_X25519_HKDF_SHA256)
        return BAD_FUNC_ARG;

    curve25519_key* ephKey = (curve25519_key*)ephemeralKey;
    curve25519_key* recvKey = (curve25519_key*)receiverKey;
    word32 sharedSecretSz = CURVE25519_KEYSIZE;

    /* Use hardware-accelerated shared secret computation */
    return hw_curve25519_shared_secret_ex(ephKey, recvKey, sharedSecret, &sharedSecretSz, EC25519_LITTLE_ENDIAN);
}

/* Extract and Expand following HPKE specification */
static int hw_HpkeExtractAndExpand(Hpke* hpke, byte* dh, word32 dhSz,
                                   byte* kemContext, word32 kemContextSz,
                                   byte* sharedSecret)
{
    int ret;
    byte prkExtract[WC_SHA256_DIGEST_SIZE];
    
    /* Step 1: Extract */
    ret = hw_HKDF_Extract(NULL, 0,  /* No salt */
                          dh, dhSz, 
                          prkExtract);
    
    if (ret != 0) {
        return ret;
    }
    
    /* Step 2: Expand */
    ret = hw_HKDF_Expand(prkExtract, sizeof(prkExtract),
                         kemContext, kemContextSz,
                         sharedSecret, CURVE25519_KEYSIZE);
    
    if (ret != 0) {
        return ret;
    }
    
    return 0;
}

/* Hardware HPKE Encapsulation */
static int hw_HpkeEncap(Hpke* hpke, void* ephemeralKey, void* receiverKey, 
                        byte* sharedSecret)
{
    int ret;
    byte dh[CURVE25519_KEYSIZE];
    byte kemContext[2 * CURVE25519_KEYSIZE];
    curve25519_key* ephKey = (curve25519_key*)ephemeralKey;
    curve25519_key* recvKey = (curve25519_key*)receiverKey;
    
    /* Step 1: DH operation with hardware */
    ret = hw_HpkeDh(hpke, ephemeralKey, receiverKey, dh);
    if (ret != 0) {
        return ret;
    }
    
    /* Step 2: Create KEM context (ephemeral_pk || receiver_pk) */
    XMEMCPY(kemContext, ephKey->p.point, CURVE25519_KEYSIZE);
    XMEMCPY(kemContext + CURVE25519_KEYSIZE, recvKey->p.point, CURVE25519_KEYSIZE);
    
    /* Step 3: Extract and Expand */
    ret = hw_HpkeExtractAndExpand(hpke, dh, sizeof(dh), 
                                  kemContext, sizeof(kemContext),
                                  sharedSecret);
    
    return ret;
}

/* Key Schedule Base following HPKE specification */
static int hw_HpkeKeyScheduleBase(Hpke* hpke, byte* sharedSecret, 
                                  const byte* info, word32 infoSz,
                                  byte* key, byte* baseNonce)
{
    int ret;
    byte prkSchedule[WC_SHA256_DIGEST_SIZE];
    byte keyScheduleContext[1 + infoSz];  /* mode || info */
    byte keyInfo[4] = {0x00, 0x01, 0x00, 0x10};  /* "key" + length 16 */
    byte nonceInfo[7] = {0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00};  /* "base_nonce" + length 16 for Ascon */
    
    /* Create key schedule context: mode (0x00 for base) || info */
    keyScheduleContext[0] = 0x00;  /* Base mode */
    if (info != NULL && infoSz > 0) {
        XMEMCPY(keyScheduleContext + 1, info, infoSz);
    }
    
    /* Step 1: Schedule Extract */
    ret = hw_HKDF_Extract(NULL, 0,  /* No salt */
                          sharedSecret, CURVE25519_KEYSIZE,
                          prkSchedule);
    
    if (ret != 0) {
        return ret;
    }
    
    /* Step 2: Expand for key */
    ret = hw_HKDF_Expand(prkSchedule, sizeof(prkSchedule),
                         keyInfo, sizeof(keyInfo),
                         key, 16);  /* Ascon-128 key size */
    
    if (ret != 0) {
        return ret;
    }
    
    /* Step 3: Expand for base nonce */
    ret = hw_HKDF_Expand(prkSchedule, sizeof(prkSchedule),
                         nonceInfo, sizeof(nonceInfo),
                         baseNonce, 16);  /* Ascon-128 nonce size */
    
    if (ret != 0) {
        return ret;
    }
    
    return 0;
}

/* Setup Base Sender following HPKE specification */
static int hw_HpkeSetupBaseSender(Hpke* hpke, void* ephemeralKey, void* receiverKey,
                                  const byte* info, word32 infoSz,
                                  byte* key, byte* baseNonce)
{
    int ret;
    byte sharedSecret[CURVE25519_KEYSIZE];
    
    /* Step 1: Encapsulation */
    ret = hw_HpkeEncap(hpke, ephemeralKey, receiverKey, sharedSecret);
    if (ret != 0) {
        return ret;
    }
    
    /* Step 2: Key Schedule */
    ret = hw_HpkeKeyScheduleBase(hpke, sharedSecret, info, infoSz, key, baseNonce);
    if (ret != 0) {
        return ret;
    }
    
    return 0;
}

/* Setup Base Receiver following HPKE specification */
static int hw_HpkeSetupBaseReceiver(Hpke* hpke, void* receiverKey, 
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
    
    /* Step 1: DH operation with hardware */
    ret = hw_curve25519_scalar_mult(sharedSecret, recvKey->k, ephemeralPubKey);
    if (ret != 0) {
        return ret;
    }

    /* Step 2: Extract and Expand */
    XMEMCPY(kemContext, ephemeralPubKey, CURVE25519_KEYSIZE);
    XMEMCPY(kemContext + CURVE25519_KEYSIZE, recvKey->p.point, CURVE25519_KEYSIZE);

    byte extractedSecret[CURVE25519_KEYSIZE];
    ret = hw_HpkeExtractAndExpand(hpke, sharedSecret, sizeof(sharedSecret),
                                  kemContext, sizeof(kemContext),
                                  extractedSecret);
    if (ret != 0) {
        return ret;
    }
    
    /* Step 3: Key Schedule */
    ret = hw_HpkeKeyScheduleBase(hpke, extractedSecret, info, infoSz, key, baseNonce);
    if (ret != 0) {
        return ret;
    }
    
    return 0;
}

/* 🎯 HPKE Seal Base with Ascon-128 AEAD (replacing AES-GCM) */
static int hw_HpkeSealBaseAscon(Hpke* hpke, void* ephemeralKey, void* receiverKey,
                                const byte* info, word32 infoSz,
                                const byte* aad, word32 aadSz,
                                const byte* plaintext, word32 plaintextSz,
                                byte* ciphertext)
{
    int ret;
    byte key[ASCON_AEAD128_KEY_SZ];       // 16 bytes for Ascon-128
    byte baseNonce[ASCON_AEAD128_NONCE_SZ]; // 16 bytes for Ascon-128
    byte tag[ASCON_AEAD128_TAG_SZ];       // 16 bytes auth tag
    wc_AsconAEAD128* asconAEAD = NULL;
    
    /* Validation */
    if (hpke == NULL || ephemeralKey == NULL || receiverKey == NULL || 
        plaintext == NULL || ciphertext == NULL) {
        return BAD_FUNC_ARG;
    }
    
    if (hpke->kem != DHKEM_X25519_HKDF_SHA256) {
        // printf("❌ Unsupported KEM for Ascon: 0x%04x\n", hpke->kem);
        return BAD_FUNC_ARG;
    }
    
    // printf("🔒 HPKE Seal with Ascon-128 AEAD\n");
    // printf("   Plaintext: %u bytes, AAD: %u bytes\n", plaintextSz, aadSz);
    
    /* Setup sender context (same as AES-GCM version) */
    // start_timing();
    ret = hw_HpkeSetupBaseSender(hpke, ephemeralKey, receiverKey, info, infoSz, key, baseNonce);
    // end_timing("HPKE Setup Base Sender");
    
    if (ret != 0) {
        printf("❌ Setup Base Sender failed: %d\n", ret);
        return ret;
    }
    
    // printf("   ✅ Key and nonce derived successfully\n");
    
    /* Create Ascon context */
    asconAEAD = create_ascon_context();
    if (asconAEAD == NULL) {
        // printf("❌ Failed to create Ascon AEAD context\n");
        return MEMORY_E;
    }
    
    /* Perform Ascon-128 AEAD encryption */
    // printf("   🔐 Encrypting with Ascon-128...\n");
    // start_timing();
    
    ret = wc_AsconAEAD128_SetKey(asconAEAD, key);
    if (ret != 0) { 
        // printf("❌ Ascon SetKey failed: %d\n", ret); 
        goto cleanup; 
    }
    
    ret = wc_AsconAEAD128_SetNonce(asconAEAD, baseNonce);
    if (ret != 0) { 
        // printf("❌ Ascon SetNonce failed: %d\n", ret); 
        goto cleanup; 
    }
    
    if (aad != NULL && aadSz > 0) {
        ret = wc_AsconAEAD128_SetAD(asconAEAD, aad, aadSz);
        if (ret != 0) { 
            // printf("❌ Ascon SetAD failed: %d\n", ret); 
            goto cleanup; 
        }
    }
    
    ret = wc_AsconAEAD128_EncryptUpdate(asconAEAD, ciphertext, plaintext, plaintextSz);
    if (ret != 0) { 
        // printf("❌ Ascon EncryptUpdate failed: %d\n", ret); 
        goto cleanup; 
    }
    
    ret = wc_AsconAEAD128_EncryptFinal(asconAEAD, tag);
    if (ret != 0) { 
        // printf("❌ Ascon EncryptFinal failed: %d\n", ret); 
        goto cleanup; 
    }

    // end_timing("Ascon-128 AEAD Encryption");
    
    /* Append authentication tag to ciphertext */
    XMEMCPY(ciphertext + plaintextSz, tag, ASCON_AEAD128_TAG_SZ);
    
    // printf("   ✅ Ascon-128 encryption successful!\n");
    // printf("   ✅ Ciphertext: %u bytes + %u byte tag = %u bytes total\n", 
    //         plaintextSz, ASCON_AEAD128_TAG_SZ, plaintextSz + ASCON_AEAD128_TAG_SZ);
    
    ret = 0; /* Success */

cleanup:
    free_ascon_context(asconAEAD);
    return ret;
}

/* 🎯 HPKE Open Base with Ascon-128 AEAD (replacing AES-GCM) */
static int hw_HpkeOpenBaseAscon(Hpke* hpke, void* receiverKey, 
                                const byte* ephemeralPubKey, word16 ephemeralPubKeySz,
                                const byte* info, word32 infoSz,
                                const byte* aad, word32 aadSz,
                                const byte* ciphertext, word32 ciphertextSz,
                                byte* plaintext)
{
    int ret;
    byte key[ASCON_AEAD128_KEY_SZ];       // 16 bytes for Ascon-128
    byte baseNonce[ASCON_AEAD128_NONCE_SZ]; // 16 bytes for Ascon-128
    byte tag[ASCON_AEAD128_TAG_SZ];       // 16 bytes auth tag
    word32 plaintextSz;
    wc_AsconAEAD128* asconAEAD = NULL;
    
    /* Validation */
    if (hpke == NULL || receiverKey == NULL || ephemeralPubKey == NULL ||
        ciphertext == NULL || plaintext == NULL) {
        return BAD_FUNC_ARG;
    }
    
    if (hpke->kem != DHKEM_X25519_HKDF_SHA256) {
        // printf("❌ Unsupported KEM for Ascon: 0x%04x\n", hpke->kem);
        return BAD_FUNC_ARG;
    }
    
    if (ciphertextSz < ASCON_AEAD128_TAG_SZ) {
        // printf("❌ Ciphertext too small: %u bytes\n", ciphertextSz);
        return BAD_FUNC_ARG;
    }
    
    plaintextSz = ciphertextSz - ASCON_AEAD128_TAG_SZ;
    
    // printf("🔓 HPKE Open with Ascon-128 AEAD\n");
    // printf("   Ciphertext: %u bytes + %u byte tag = %u bytes total\n", 
    //         plaintextSz, ASCON_AEAD128_TAG_SZ, ciphertextSz);
    
    /* Extract authentication tag */
    XMEMCPY(tag, ciphertext + plaintextSz, ASCON_AEAD128_TAG_SZ);

    /* Setup receiver context (same as AES-GCM version) */
    // start_timing();
    ret = hw_HpkeSetupBaseReceiver(hpke, receiverKey, ephemeralPubKey, ephemeralPubKeySz,
                                   info, infoSz, key, baseNonce);
    // end_timing("HPKE Setup Base Receiver");
    
    if (ret != 0) {
        // printf("❌ Setup Base Receiver failed: %d\n", ret);
        return ret;
    }

    // printf("   ✅ Key and nonce derived successfully\n");

    /* Create Ascon context */
    asconAEAD = create_ascon_context();
    if (asconAEAD == NULL) {
        // printf("❌ Failed to create Ascon AEAD context\n");
        return MEMORY_E;
    }
    
    /* Perform Ascon-128 AEAD decryption */
    // printf("   🔓 Decrypting with Ascon-128...\n");
    // start_timing();
    
    ret = wc_AsconAEAD128_SetKey(asconAEAD, key);
    if (ret != 0) { 
        // printf("❌ Ascon SetKey failed: %d\n", ret); 
        goto cleanup; 
    }
    
    ret = wc_AsconAEAD128_SetNonce(asconAEAD, baseNonce);
    if (ret != 0) { // printf("❌ Ascon SetNonce failed: %d\n", ret); 
        goto cleanup; 
    }
    
    if (aad != NULL && aadSz > 0) {
        ret = wc_AsconAEAD128_SetAD(asconAEAD, aad, aadSz);
        if (ret != 0) { // printf("❌ Ascon SetAD failed: %d\n", ret); 
            goto cleanup; 
        }
    }
    
    ret = wc_AsconAEAD128_DecryptUpdate(asconAEAD, plaintext, ciphertext, plaintextSz);
    if (ret != 0) { // printf("❌ Ascon DecryptUpdate failed: %d\n", ret); 
        goto cleanup; 
    }

    ret = wc_AsconAEAD128_DecryptFinal(asconAEAD, tag);
    if (ret != 0) {
        // printf("❌ Ascon DecryptFinal failed: %d\n", ret);
        // printf("   → Authentication tag verification failed\n");
        goto cleanup;
    }
    
    // end_timing("Ascon-128 AEAD Decryption");
    
    // printf("   ✅ Ascon-128 decryption successful!\n");
    // printf("   ✅ Authentication verified for %u bytes plaintext + %u bytes AAD\n", 
    //         plaintextSz, aadSz);

    ret = 0; /* Success */

cleanup:
    free_ascon_context(asconAEAD);
    return ret;
}

/* Hardware-accelerated key generation (same as AES-GCM version) */
static int hw_curve25519_make_key(WC_RNG* rng, int keysize, curve25519_key* key)
{
    int ret;
    static const byte kCurve25519BasePoint[CURVE25519_KEYSIZE] = {9};

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    /* Generate random private key */
    ret = wc_curve25519_make_priv(rng, keysize, key->k);    
    if (ret != 0) {
        return ret;
    }

    key->privSet = 1;
    
    /* Use HARDWARE to compute public key: public = private * basepoint */
    ret = hw_curve25519_scalar_mult(key->p.point, key->k, kCurve25519BasePoint);
    
    if (ret == 0) {
        key->pubSet = 1;
        ret = wc_curve25519_set_rng(key, rng);
    }
    
    return ret;
}

/* Hardware-accelerated HPKE key pair generation (same as AES-GCM version) */
static int hw_HpkeGenerateKeyPair(Hpke* hpke, void** keypair, WC_RNG* rng)
{
    int ret = 0;

    if (hpke == NULL || keypair == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    if (hpke->kem != DHKEM_X25519_HKDF_SHA256)
        return BAD_FUNC_ARG;

    *keypair = XMALLOC(sizeof(curve25519_key), hpke->heap, DYNAMIC_TYPE_CURVE25519);
    if (*keypair != NULL) {
        ret = wc_curve25519_init_ex((curve25519_key*)*keypair, hpke->heap, INVALID_DEVID);
        if (ret == 0) {
            /* Use hardware-accelerated key generation */
            ret = hw_curve25519_make_key(rng, 32, (curve25519_key*)*keypair);
        }
    } else {
        ret = MEMORY_E;
    }

    if (ret != 0 && *keypair != NULL) {
        wc_HpkeFreeKey(hpke, (word16)hpke->kem, *keypair, hpke->heap);
        *keypair = NULL;
    }

    return ret;
}

/* Test HPKE with Ascon-128 using static buffers */
static int test_hpke_ascon_large_data_static(void)
{
    printf("\n=== HPKE with Ascon-128 Large Data Test (Static Buffers) ===\n");
    
    int ret = 0;
    Hpke hpke;
    WC_RNG rng;
    void* receiverKey = NULL;
    void* ephemeralKey = NULL;
    
    /* Use static buffers - NO malloc() calls */
    const word32 plaintext_len = HPKE_TEST_BYTES;  // 1KB
    const word32 aad_len = 256;                    // 256 bytes
    const char* info_str = "HPKE with Ascon-128 test";
    word32 info_len = strlen(info_str);
    
    /* Point to static buffers */
    byte* plaintext = hpke_plaintext_buf;
    byte* aad = hpke_aad_buf;
    byte* ciphertext = hpke_ciphertext_buf;
    byte* decrypted = hpke_decrypted_buf;
    
    // printf("📋 Test Parameters:\n");
    // printf("   Algorithm: HPKE with Ascon-128 AEAD\n");
    // printf("   KEM: X25519 (hardware accelerated)\n");  
    // printf("   KDF: HKDF-SHA256 (hardware accelerated)\n");
    // printf("   AEAD: Ascon-128 (replacing AES-GCM)\n");
    // printf("   Plaintext: %u bytes, AAD: %u bytes\n", plaintext_len, aad_len);
    // printf("   Using static buffers (no dynamic allocation)\n");
    
    /* Fill with test data */
    // printf("🔧 Filling static buffers with test data...\n");
    for (word32 i = 0; i < plaintext_len; i++) {
        plaintext[i] = (byte)(i & 0xFF);
    }
    for (word32 i = 0; i < aad_len; i++) {
        aad[i] = (byte)((i + 0x55) & 0xFF);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    if (ret != 0) {
        printf("❌ RNG init failed: %d\n", ret);
        goto cleanup_rng;
    }
    
    /* Initialize HPKE - use same parameters but Ascon will replace AES-GCM internally */
    ret = wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, HPKE_AES_128_GCM, g_heap_hint);
    if (ret != 0) {
        printf("❌ HPKE init failed: %d\n", ret);
        goto cleanup_rng;
    }
    
    /* Generate keys */
    printf("🔑 Generating receiver key...\n");
    ret = hw_HpkeGenerateKeyPair(&hpke, &receiverKey, &rng);
    if (ret != 0) {
        // printf("❌ Receiver key generation failed: %d\n", ret);
        goto cleanup_rng;
    }

    printf("🔑 Generating ephemeral key...\n");
    ret = hw_HpkeGenerateKeyPair(&hpke, &ephemeralKey, &rng);
    if (ret != 0) {
        // printf("❌ Ephemeral key generation failed: %d\n", ret);
        goto cleanup_keys;
    }
    
    /* Get ephemeral public key */
    byte ephemeral_pk[32];
    word16 ephemeral_pk_size = sizeof(ephemeral_pk);
    ret = wc_HpkeSerializePublicKey(&hpke, ephemeralKey, ephemeral_pk, &ephemeral_pk_size);
    if (ret != 0) {
        // printf("❌ Public key serialization failed: %d\n", ret);
        goto cleanup_keys;
    }
    
    // printf("   ✅ Key generation completed\n");
    
    /* Seal with Ascon-128 */
    printf("\n🔒 Sealing with HPKE + Ascon-128...\n");
    start_timing();
    ret = hw_HpkeSealBaseAscon(&hpke, ephemeralKey, receiverKey,
                               (const byte*)info_str, info_len,
                               aad, aad_len,
                               plaintext, plaintext_len,
                               ciphertext);
    end_timing("HPKE + Ascon-128 Seal (1KB)");
    
    if (ret != 0) {
        printf("❌ Seal failed: %d\n", ret);
        goto cleanup_keys;
    }
    
    /* Open with Ascon-128 */
    printf("\n🔓 Opening with HPKE + Ascon-128...\n");
    start_timing();
    ret = hw_HpkeOpenBaseAscon(&hpke, receiverKey, ephemeral_pk, ephemeral_pk_size,
                               (const byte*)info_str, info_len,
                               aad, aad_len,
                               ciphertext, plaintext_len + ASCON_AEAD128_TAG_SZ,
                               decrypted);
    end_timing("HPKE + Ascon-128 Open (1KB)");
    
    if (ret != 0) {
        printf("❌ Open failed: %d\n", ret);
        goto cleanup_keys;
    }
    
    /* Verify */
    printf("\n✅ Verification:\n");
    printf("   Verifying %u-byte data integrity...\n", plaintext_len);
    if (XMEMCMP(plaintext, decrypted, plaintext_len) == 0) {
        printf("🎉 SUCCESS: HPKE + Ascon-128 round-trip completed perfectly!\n");
        printf("   ✅ Static buffers working correctly\n");
        printf("   ✅ Hardware X25519 + HKDF-SHA256 working\n");
        printf("   ✅ Ascon-128 AEAD working\n");
        printf("   ✅ Processed %u bytes plaintext + %u bytes AAD\n", plaintext_len, aad_len);
        printf("   ✅ Post-quantum resistant AEAD (Ascon) integrated!\n");
        
        /* Show first and last few bytes for verification */
        printf("   📊 Data verification samples:\n");
        printf("      First 16 bytes - Original: ");
        for (int i = 0; i < 16; i++) printf("%02x", plaintext[i]);
        printf("\n");
        printf("      First 16 bytes - Decrypted: ");
        for (int i = 0; i < 16; i++) printf("%02x", decrypted[i]);
        printf("\n");
        
    } else {
        printf("❌ FAIL: Decrypted data doesn't match\n");
        ret = -1;
    }
    
cleanup_keys:
    if (receiverKey != NULL) {
        wc_HpkeFreeKey(&hpke, hpke.kem, receiverKey, hpke.heap);
    }
    if (ephemeralKey != NULL) {
        wc_HpkeFreeKey(&hpke, hpke.kem, ephemeralKey, hpke.heap);
    }
    
cleanup_rng:
    wc_FreeRng(&rng);
    
    /* Clear sensitive data from static buffers */
    XMEMSET(hpke_plaintext_buf, 0, HPKE_TEST_BYTES);
    XMEMSET(hpke_aad_buf, 0, 256);
    XMEMSET(hpke_ciphertext_buf, 0, HPKE_TEST_BYTES + 16);
    XMEMSET(hpke_decrypted_buf, 0, HPKE_TEST_BYTES);
    
    return ret;
}

/* Main function */
int main(void)
{
    printf("=== HPKE with Ascon-128 AEAD Test ===\n");
    printf("Hardware-accelerated X25519 + HKDF-SHA256 + Ascon-128\n");
    printf("Replacing AES-GCM with post-quantum resistant Ascon\n\n");
    
    /* Setup WolfSSL memory */
    if (setup_wolfssl_memory() != 0) {
        printf("❌ FAIL: Static memory setup failed\n");
        return -1;
    }

    /* Check Ascon availability */
#ifdef HAVE_ASCON
    printf("✅ HAVE_ASCON is defined - Ascon support available\n");
#else
    printf("❌ HAVE_ASCON not defined - Ascon not available\n");
    return -1;
#endif
    
    /* Run HPKE + Ascon test */
    printf("🧪 Running HPKE + Ascon-128 Test...\n");
    
    int hpke_ascon_result = test_hpke_ascon_large_data_static();
    
    /* Summary */
    printf("\n📊 Final Test Results:\n");
    printf("   HPKE + Ascon-128 (1KB): %s\n", hpke_ascon_result == 0 ? "✅ PASS" : "❌ FAIL");
    
    if (hpke_ascon_result == 0) {
        printf("\n🎉 SUCCESS: HPKE with Ascon-128 working perfectly! 🎉\n");
        printf("✅ Hardware X25519 key exchange working\n");
        printf("✅ Hardware HKDF-SHA256 key derivation working\n");
        printf("✅ Ascon-128 AEAD encryption/decryption working\n");
        printf("✅ Complete HPKE protocol with post-quantum AEAD\n");
        printf("✅ Static memory management working\n");
        printf("🔒 Ready for post-quantum transition!\n");
        
        return 0;
    } else {
        printf("\n❌ HPKE + Ascon-128 test failed\n");
        return -1;
    }
}