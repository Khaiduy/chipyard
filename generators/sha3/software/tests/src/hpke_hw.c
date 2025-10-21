/* test_hpke_x25519_sha256_aes128gcm_hw_proper.c
 * Proper HPKE implementation with hardware acceleration
 * Following WolfSSL HPKE structure closely
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
// #include <wolfssl/wolfcrypt/kdf.h>
// #include <wolfssl/wolfcrypt/aes.h>
#include "driver/aes_gcm/aes_gcm.h"  // add: firmware AES-GCM API
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

// #ifndef XMALLOC
// #define XMALLOC(sz, heap, type) malloc(sz)
// #endif

// #ifndef XFREE
// #define XFREE(ptr, heap, type) free(ptr)
// #endif

/* Hardware accelerator base addresses */
#define X25519_HW_BASE_ADDR  0x64004000
#define AES_GCM_HW_BASE_ADDR 0x64009000
#define HMAC_SHA_HW_BASE_ADDR 0x64005000

#define SHA256_MODE 1

// Static memory setup for WolfSSL
#define WOLFSSL_STATIC_MEM_SIZE 1024*32
static byte g_wolfssl_mem[WOLFSSL_STATIC_MEM_SIZE];
static WOLFSSL_HEAP_HINT* g_heap_hint = NULL;

// Test result tracking
static int test_failures = 0;
static int tests_passed = 0;
static unsigned long total_cycles = 0;
static unsigned long step_start_cycles = 0;

#define HPKE_TEST_BYTES (1 * 128)  // 128 bytes test size

#define HPKE_TEST_WORDS64 ((HPKE_TEST_BYTES + 7) / 8)  // Convert to qwords

/* Static buffers for HPKE large data test */
static byte hpke_plaintext_buf[HPKE_TEST_BYTES];     // 128 bytes
static byte hpke_aad_buf[16];                       // 16 bytes AAD
static byte hpke_ciphertext_buf[HPKE_TEST_BYTES + 16]; // 128 bytes + 16-byte tag
static byte hpke_decrypted_buf[HPKE_TEST_BYTES];     // 128 bytes

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

/* Hardware-accelerated scalar multiplication - ONLY hardware part */
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

    /* Use hardware for the scalar multiplication */
    // printf("    Using hardware for Curve25519 shared secret computation\n");
    // start_timing();
    int ret = hw_curve25519_scalar_mult(out, private_key->k, public_key->p.point);
    // end_timing("Hardware Curve25519 shared secret");
    
    if (ret == 0) {
        *outlen = CURVE25519_KEYSIZE;
        
        /* Handle endianness if needed (keeping original logic) */
        if (endian == EC25519_LITTLE_ENDIAN) {
            /* WolfSSL typically uses little endian, so we might need to reverse */
            /* For now, assume hardware returns in correct format */
        }
    }
    
    return ret;
}


/* Hardware HKDF Extract using hmacsha_compute */
static int hw_HKDF_Extract(const byte* salt, word32 saltSz,
                                        const byte* ikm, word32 ikmSz,
                                        byte* prk)
{
    // printf("\n=== Hardware HKDF Extract (hmacsha_compute) ===\n");
    // printf("Salt size: %u bytes\n", saltSz);
    // printf("IKM size: %u bytes\n", ikmSz);
    
    void* hmac_shactrl = (void*)HMAC_SHA_HW_BASE_ADDR;
    uint64_t hw_key[8] = {0};      /* HMAC key (salt or zeros) */
    uint64_t hw_msg[16] = {0};     /* HMAC message (IKM) */
    uint64_t hw_mac[8] = {0};      /* HMAC output (PRK) */
    
    /* Validate input sizes */
    // if (saltSz > 64) {
    //     printf("ERROR: Salt too large (max 64 bytes)\n");
    //     return -1;
    // }
    // if (ikmSz > 64) {  /* Vietnamese pattern: 16 qwords × 4 bytes = 64 bytes max */
    //     printf("ERROR: IKM too large (max 64 bytes with Vietnamese pattern)\n");
    //     return -1;
    // }
    
    /* Prepare HMAC key (salt) - Vietnamese pattern with zero padding */
    if (salt != NULL && saltSz > 0) {
        // printf("Using provided salt as HMAC key:\n");
        for (word32 i = 0; i < saltSz; i++) {
            word32 qw_idx = i / 4;           /* Each qword holds 4 bytes */
            word32 byte_idx = 3 - (i % 4);   /* Big-endian within 32 bits */
            
            if (qw_idx < 8) {
                /* Put data in LOWER 32 bits, keep UPPER 32 bits as zero */
                hw_key[qw_idx] |= ((uint64_t)salt[i]) << (8 * byte_idx);
            }
        }
        
        // for (int i = 0; i < 8; i++) {
        //     if (hw_key[i] != 0) {
        //         printf("  key[%d] = 0x%016llx\n", i, hw_key[i]);
        //     }
        // }
    } 
    // else {
    //     /* RFC 5869: If salt is NULL, use zero-filled key */
    //     printf("No salt provided, using zero-filled HMAC key\n");
    //     /* hw_key already initialized to zeros */
    // }
    
    /* Prepare HMAC message (IKM) - Vietnamese pattern with zero padding */
    // printf("Packing IKM as HMAC message:\n");
    for (word32 i = 0; i < ikmSz; i++) {
        word32 qw_idx = i / 4;           /* Each qword holds 4 bytes */
        word32 byte_idx = 3 - (i % 4);   /* Big-endian within 32 bits */
        
        if (qw_idx < 16) {
            /* Put data in LOWER 32 bits, keep UPPER 32 bits as zero */
            hw_msg[qw_idx] |= ((uint64_t)ikm[i]) << (8 * byte_idx);
        }
    }
    
    // for (int i = 0; i < 16; i++) {
    //     if (hw_msg[i] != 0) {
    //         printf("  msg[%d] = 0x%016llx\n", i, hw_msg[i]);
    //     }
    // }
    
    /* Execute HMAC with hardware using unified function */
    // printf("Calling hmacsha_compute...\n");
    int ret = hmacsha_compute(hmac_shactrl, 
                             SHA256_MODE,           /* Hash type */
                             hw_key,           /* Key */
                             hw_msg,           /* Message */
                             ikmSz * 8,        /* Message size in bits */
                             hw_mac);          /* Output MAC */
    
    if (ret != 0) {
        // printf("hmacsha_compute failed: %d\n", ret);
        return ret;
    }
    
    // for (int i = 0; i < 8; i++) {
    //     printf("  mac256[%d] = 0x%016llx\n", i, hw_mac[i]);
    // }

    /* Convert result back to bytes */
    for (int i = 0; i < 8; i++) {
        uint32_t val = (uint32_t)(hw_mac[i] & 0xFFFFFFFF);
        prk[i*4+0] = (val >> 24) & 0xFF;
        prk[i*4+1] = (val >> 16) & 0xFF; 
        prk[i*4+2] = (val >> 8)  & 0xFF;
        prk[i*4+3] = (val >> 0)  & 0xFF;
    }
    
    // printf("Hardware HMAC result (PRK):\n");
    // for (int i = 0; i < 8; i++) {
    //     printf("  mac[%d] = 0x%016llx\n", i, hw_mac[i]);
    // }
    
    return 0; /* Success */
}

/* Hardware HKDF Expand using static buffers for baremetal */
static int hw_HKDF_Expand(const byte* prk, word32 prkSz,
                          const byte* info, word32 infoSz,
                          byte* okm, word32 okmSz)
{
    // printf("\n=== Hardware HKDF Expand (Static Buffers) ===\n");
    // printf("PRK size: %u bytes\n", prkSz);
    // printf("Info size: %u bytes\n", infoSz);
    // printf("OKM size: %u bytes\n", okmSz);
    
    void* hmac_shactrl = (void*)HMAC_SHA_HW_BASE_ADDR;
    uint64_t hw_key[8] = {0};      /* HMAC key (PRK) */
    uint64_t hw_mac[8] = {0};      /* HMAC output */
    
    /* Static buffers to avoid malloc() */
    static uint64_t hw_msg_buffer[64];  /* Max 512 bytes = 64 qwords */
    static byte msg_bytes_buffer[512];  /* Max 512 bytes message */
    
    /* Validate input sizes */
    if (prkSz != 32) {
        // printf("ERROR: PRK must be 32 bytes for SHA256\n");
        return -1;
    }
    if (okmSz > 255 * 32) {
        // printf("ERROR: OKM too large (max 255 * hash_len)\n");
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
    
    // printf("HKDF-Expand will perform %u iterations\n", n);
    
    for (word32 i = 1; i <= n; i++) {
        // printf("\n--- Iteration %u ---\n", i);
        
        /* Calculate total message size for this iteration */
        word32 msg_len = 0;
        if (i > 1) {
            msg_len += hash_len;  /* T(i-1) */
        }
        msg_len += infoSz;        /* info */
        msg_len += 1;             /* counter */
        
        // printf("  Total message length: %u bytes\n", msg_len);
        
        /* Check if message fits in static buffer */
        if (msg_len > sizeof(msg_bytes_buffer)) {
            // printf("  ERROR: Message too large (%u > %u bytes)\n", 
                //    msg_len, (unsigned)sizeof(msg_bytes_buffer));
            return -1;
        }
        
        word32 msg_qwords = (msg_len + 3) / 4;  /* Convert to qwords */
        if (msg_qwords > sizeof(hw_msg_buffer)/sizeof(hw_msg_buffer[0])) {
            // printf("  ERROR: Message requires too many qwords (%u > %u)\n", 
                //    msg_qwords, (unsigned)(sizeof(hw_msg_buffer)/sizeof(hw_msg_buffer[0])));
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
            // printf("  Added T(%u) (%u bytes)\n", i-1, hash_len);
        }
        
        /* Add info */
        if (info != NULL && infoSz > 0) {
            XMEMCPY(msg_bytes + offset, info, infoSz);
            offset += infoSz;
            // printf("  Added info (%u bytes)\n", infoSz);
        }
        
        /* Add counter byte */
        msg_bytes[offset] = (byte)i;
        offset += 1;
        // printf("  Added counter: %u\n", i);
        
        /* Pack into Vietnamese pattern */
        for (word32 j = 0; j < msg_len; j++) {
            word32 qw_idx = j / 4;
            word32 byte_idx = 3 - (j % 4);
            if (qw_idx < msg_qwords) {
                hw_msg[qw_idx] |= ((uint64_t)msg_bytes[j]) << (8 * byte_idx);
            }
        }
        
        // /* ADD THIS DEBUG BLOCK */
        // printf("  DEBUG: msg_bytes after construction:\n    ");
        // for (word32 k = 0; k < msg_len; k++) {
        //     printf("%02x", msg_bytes[k]);
        // }
        // printf(" (%u bytes)\n", msg_len);

        // printf("  DEBUG: hw_msg after packing:\n");
        // for (word32 k = 0; k < 3; k++) {
        //     printf("    hw_msg[%u] = 0x%016llx\n", k, hw_msg[k]);
        // }


        /* Execute HMAC with hardware - chunking handled automatically */
        // printf("  Calling hmacsha_compute (handles chunking automatically)...\n");
        int ret = hmacsha_compute(hmac_shactrl, 
                                 SHA256_MODE,         /* Hash type */
                                 hw_key,              /* Key (PRK) */
                                 hw_msg,              /* Message (auto-chunked) */
                                 msg_len * 8,         /* Message size in bits */
                                 hw_mac);             /* Output MAC */
        


        if (ret != 0) {
            // printf("  hmacsha_compute failed: %d\n", ret);
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
        
        // printf("  T(%u) computation successful\n", i);
        
        /* Copy appropriate amount to output */
        word32 copy_len = (okmSz - okm_offset > hash_len) ? hash_len : (okmSz - okm_offset);
        XMEMCPY(okm + okm_offset, t_current, copy_len);
        okm_offset += copy_len;
        
        // printf("  Copied %u bytes to OKM (total: %u bytes)\n", copy_len, okm_offset);
        
        /* Save for next iteration */
        XMEMCPY(t_prev, t_current, hash_len);
        
        /* Break if we have enough output */
        if (okm_offset >= okmSz) {
            // printf("  Generated enough OKM (%u bytes)\n", okm_offset);
            break;
        }
    }
    XMEMSET(hw_msg_buffer, 0, sizeof(hw_msg_buffer));  /* Clear entire static buffer */
    XMEMSET(msg_bytes_buffer, 0, sizeof(msg_bytes_buffer));  /* Clear entire static buffer */
    // printf("Hardware HKDF Expand completed successfully\n");
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

    // printf("  Performing DH operation with hardware acceleration\n");
    
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
    
    // printf("  Extract and Expand operation\n");
    
    /* Step 1: Extract */
    printf("    HKDF Extract step\n");
    start_timing();
    ret = hw_HKDF_Extract(NULL, 0,  /* No salt */
                          dh, dhSz, 
                          prkExtract);
    end_timing("HKDF Extract");
    
    if (ret != 0) {
        // printf("    HKDF Extract failed: %d\n", ret);
        return ret;
    }
    
    /* Step 2: Expand */
    // printf("    HKDF Expand step\n");
    start_timing();
    ret = hw_HKDF_Expand(prkExtract, sizeof(prkExtract),
                         kemContext, kemContextSz,
                         sharedSecret, CURVE25519_KEYSIZE);
    end_timing("HKDF Expand");
    
    if (ret != 0) {
        // printf("    HKDF Expand failed: %d\n", ret);
        return ret;
    }
    
    // printf("  Extract and Expand completed successfully\n");
    return 0;
}


/* Modified hw_HpkeEncap with complete debug output */
static int hw_HpkeEncap(Hpke* hpke, void* ephemeralKey, void* receiverKey, 
                        byte* sharedSecret)
{
    int ret;
    byte dh[CURVE25519_KEYSIZE];
    byte kemContext[2 * CURVE25519_KEYSIZE];
    curve25519_key* ephKey = (curve25519_key*)ephemeralKey;
    curve25519_key* recvKey = (curve25519_key*)receiverKey;
    
    // printf("  === HPKE Encapsulation DEBUG ===\n");
    
    /* Debug: Print input keys */
    // print_key_debug("Ephemeral Key Input", ephKey);
    // print_key_debug("Receiver Key Input", recvKey);
    
    /* Step 1: DH operation with hardware */
    // printf("    Step 1: DH operation\n");
    // printf("    Computing: dh = ephemeral_private * receiver_public\n");
    ret = hw_HpkeDh(hpke, ephemeralKey, receiverKey, dh);
    if (ret != 0) {
        // printf("    DH operation failed: %d\n", ret);
        return ret;
    }
    
    /* Debug: Print DH result */
    // print_hex_debug("DH shared secret", dh, CURVE25519_KEYSIZE);
    
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
    ret = hw_HpkeExtractAndExpand(hpke, dh, sizeof(dh), 
                                  kemContext, sizeof(kemContext),
                                  sharedSecret);
    
    // if (ret == 0) {
    //     /* Debug: Print final shared secret */
    //     // print_hex_debug("Final HPKE shared secret", sharedSecret, CURVE25519_KEYSIZE);
    //     // printf("  === Encapsulation completed successfully ===\n");
    // } else {
    //     // printf("  Encapsulation failed: %d\n", ret);
    // }
    
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
    byte nonceInfo[7] = {0x00, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x00};  /* "base_nonce" + length 12 */
    
    // printf("  HPKE Key Schedule Base\n");
    
    /* Create key schedule context: mode (0x00 for base) || info */
    keyScheduleContext[0] = 0x00;  /* Base mode */
    if (info != NULL && infoSz > 0) {
        XMEMCPY(keyScheduleContext + 1, info, infoSz);
    }
    
    /* Step 1: Schedule Extract */
    // printf("    Schedule Extract step\n");
    start_timing();
    ret = hw_HKDF_Extract(NULL, 0,  /* No salt */
                          sharedSecret, CURVE25519_KEYSIZE,
                          prkSchedule);
    // end_timing("Schedule HKDF Extract");
    
    if (ret != 0) {
        // printf("    Schedule Extract failed: %d\n", ret);
        return ret;
    }
    
    /* Step 2: Expand for key */
    // printf("    Expand for key\n");
    start_timing();
    ret = hw_HKDF_Expand(prkSchedule, sizeof(prkSchedule),
                         keyInfo, sizeof(keyInfo),
                         key, 16);  /* AES-128 key size */
    // end_timing("Key HKDF Expand");
    
    if (ret != 0) {
        // printf("    Key expand failed: %d\n", ret);
        return ret;
    }
    
    /* Step 3: Expand for base nonce */
    // printf("    Expand for base nonce\n");
    start_timing();
    ret = hw_HKDF_Expand(prkSchedule, sizeof(prkSchedule),
                         nonceInfo, sizeof(nonceInfo),
                         baseNonce, 12);  /* GCM nonce size */
    // end_timing("Nonce HKDF Expand");
    
    if (ret != 0) {
        // printf("    Nonce expand failed: %d\n", ret);
        return ret;
    }
    
    // printf("  Key Schedule Base completed successfully\n");
    return 0;
}

/* Setup Base Sender following HPKE specification */
static int hw_HpkeSetupBaseSender(Hpke* hpke, void* ephemeralKey, void* receiverKey,
                                  const byte* info, word32 infoSz,
                                  byte* key, byte* baseNonce)
{
    int ret;
    byte sharedSecret[CURVE25519_KEYSIZE];
    
    // printf("HPKE Setup Base Sender (Hardware Accelerated)\n");
    
    /* Step 1: Encapsulation */
    // printf("Step 1: Encapsulation\n");
    start_timing();
    ret = hw_HpkeEncap(hpke, ephemeralKey, receiverKey, sharedSecret);
    if (ret != 0) {
        // printf("Encapsulation failed: %d\n", ret);
        return ret;
    }
    // end_timing("Hardware Encapsulation");
    
    /* Step 2: Key Schedule */
    // printf("Step 2: Key Schedule\n");
    start_timing();
    ret = hw_HpkeKeyScheduleBase(hpke, sharedSecret, info, infoSz, key, baseNonce);
    if (ret != 0) {
        // printf("Key Schedule failed: %d\n", ret);
        return ret;
    }
    // end_timing("Hardware Key Schedule");
    
    // printf("Setup Base Sender completed successfully\n");
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
    
    // printf("=== HPKE Setup Base Receiver (Hardware) DEBUG ===\n");
    
    /* Debug: Print inputs */
    // print_key_debug("Receiver Key Input", recvKey);
    // print_hex_debug("Ephemeral public key input", ephemeralPubKey, ephemeralPubKeySz);
    // if (info != NULL && infoSz > 0) {
    //     print_hex_debug("Info parameter", info, infoSz);
    // }
    
    if (ephemeralPubKeySz != CURVE25519_KEYSIZE) {
        // printf("Invalid ephemeral public key size: %u\n", ephemeralPubKeySz);
        return BAD_FUNC_ARG;
    }
    
    /* Step 1: DH operation with hardware */
    printf("Step 1: DH operation\n");
    start_timing();
    ret = hw_curve25519_scalar_mult(sharedSecret, recvKey->k, ephemeralPubKey);
    
    
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
    ret = hw_HpkeExtractAndExpand(hpke, sharedSecret, sizeof(sharedSecret),
                                  kemContext, sizeof(kemContext),
                                  extractedSecret);
    if (ret != 0) {
        // printf("Extract and Expand failed: %d\n", ret);
        return ret;
    }
    end_timing("Hardware DH operation");
    /* Step 3: Key Schedule */
    printf("Step 3: Key Schedule\n");
    start_timing();
    ret = hw_HpkeKeyScheduleBase(hpke, extractedSecret, info, infoSz, key, baseNonce);
    if (ret != 0) {
        // printf("Key Schedule failed: %d\n", ret);
        return ret;
    }
    end_timing("Hardware Key Schedule");
    // printf("Setup Base Receiver completed successfully\n");
    return 0;
}

/* Pack bytes -> qwords (big-endian per 64-bit word) */
static void pack_bytes_to_qwords_be_fixed(const byte* in, word32 len, uint64_t* out, word32 qwords)
{
    /* Clear output buffer */
    for (word32 w = 0; w < qwords; ++w) out[w] = 0;
    
    /* Pack bytes into qwords */
    for (word32 i = 0; i < len; ++i) {
        word32 w = i / 8;           /* which qword */
        word32 off = i % 8;         /* offset within qword */
        
        if (w < qwords) {
            out[w] |= ((uint64_t)in[i]) << (8 * (7 - off));
        }
    }
    
    /* Handle partial qwords correctly - move remaining bytes to low bits if needed */
    word32 last_qword = (len - 1) / 8;
    word32 bytes_in_last = len % 8;
    
    if (bytes_in_last != 0 && last_qword < qwords) {
        /* Move the partial qword content to match your direct format */
        uint64_t temp = out[last_qword];
        out[last_qword] = 0;
        
        /* Rebuild with correct positioning */
        for (word32 i = last_qword * 8; i < len; ++i) {
            word32 off = i % 8;
            if (bytes_in_last <= 4) {
                /* Put in high 32 bits like your direct method */
                out[last_qword] |= ((uint64_t)in[i]) << (8 * (7 - off));
            } else {
                /* Normal big-endian packing */
                out[last_qword] |= ((uint64_t)in[i]) << (8 * (7 - off));
            }
        }
        
        /* For IV specifically (12 bytes = 1.5 qwords), match direct format */
        if (len == 12 && last_qword == 1) {
            /* Extract the last 4 bytes and put them in low 32 bits */
            uint32_t last_4_bytes = 0;
            for (int i = 8; i < 12; i++) {
                last_4_bytes = (last_4_bytes << 8) | in[i];
            }
            out[1] = (uint64_t)last_4_bytes;  /* 0x00000000b2c28465 */
        }
    }
}


/* Unpack qwords -> bytes (big-endian per 64-bit word) */
static void unpack_qwords_to_bytes_be(const uint64_t* in, word32 bytes, byte* out)
{
    for (word32 i = 0; i < bytes; ++i) {
        word32 w = i >> 3;
        word32 off = i & 7;
        out[i] = (byte)((in[w] >> (8 * (7 - off))) & 0xFF);
    }
}
/* Hardware AES-GCM Seal Base with dynamic allocation */
static int hw_HpkeSealBase(Hpke* hpke, void* ephemeralKey, void* receiverKey,
                           const byte* info, word32 infoSz,
                           const byte* aad, word32 aadSz,
                           const byte* plaintext, word32 plaintextSz,
                           byte* ciphertext)
{
    int ret;
    byte key[16];
    byte baseNonce[12];
    byte authTag[16];
    
    /* Hardware AES-GCM controller address */
    void* aes_gcmctrl = (void*)AES_GCM_HW_BASE_ADDR;
    
    /* Calculate required qwords dynamically */
    word32 aad_qwords = (aadSz + 7) / 8;
    word32 pt_qwords = (plaintextSz + 7) / 8;
    
    /* Dynamic allocation based on actual data size */
    uint64_t hw_key[4] = {0};      /* AES-128 always uses 4 qwords */
    uint64_t hw_iv[2] = {0};       /* 12-byte nonce always uses 2 qwords */
    uint64_t hw_tag[2] = {0};      /* 16-byte auth tag always uses 2 qwords */
    
    /* Dynamically allocate AAD buffer */
    uint64_t* hw_aad = NULL;
    if (aadSz > 0) {
        hw_aad = XMALLOC(aad_qwords * sizeof(uint64_t), hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (hw_aad == NULL) {
            // printf("Failed to allocate AAD buffer (%u qwords)\n", aad_qwords);
            return MEMORY_E;
        }
        XMEMSET(hw_aad, 0, aad_qwords * sizeof(uint64_t));
    }
    
    /* Dynamically allocate plaintext/ciphertext buffers */
    uint64_t* hw_pt = XMALLOC(pt_qwords * sizeof(uint64_t), hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    uint64_t* hw_ct = XMALLOC(pt_qwords * sizeof(uint64_t), hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    
    if (hw_pt == NULL || hw_ct == NULL) {
        // printf("Failed to allocate plaintext/ciphertext buffers (%u qwords each)\n", pt_qwords);
        ret = MEMORY_E;
        goto cleanup;
    }
    
    XMEMSET(hw_pt, 0, pt_qwords * sizeof(uint64_t));
    XMEMSET(hw_ct, 0, pt_qwords * sizeof(uint64_t));
    
    /* Validation */
    if (hpke == NULL || ephemeralKey == NULL || receiverKey == NULL || 
        plaintext == NULL || ciphertext == NULL) {
        // printf("Invalid parameters\n");
        ret = BAD_FUNC_ARG;
        goto cleanup;
    }
    
    if (hpke->kem != DHKEM_X25519_HKDF_SHA256) {
        // printf("Unsupported KEM: 0x%04x\n", hpke->kem);
        ret = BAD_FUNC_ARG;
        goto cleanup;
    }
    
    /* Setup sender context */
    ret = hw_HpkeSetupBaseSender(hpke, ephemeralKey, receiverKey, info, infoSz, key, baseNonce);
    if (ret != 0) {
        // printf("Setup Base Sender failed: %d\n", ret);
        goto cleanup;
    }
    
    printf("Sealing with AES-GCM using hardware acceleration\n");
    start_timing();
    /* Convert to hardware format */
    pack_bytes_to_qwords_be_fixed(key, 16, hw_key, 4);
    pack_bytes_to_qwords_be_fixed(baseNonce, 12, hw_iv, 2);
    
    /* Pack AAD if present */
    if (aad != NULL && aadSz > 0) {
        /* Manual byte-by-byte packing for consistency */
        for (word32 i = 0; i < aadSz; i++) {
            word32 qw_idx = i / 8;
            word32 byte_idx = 7 - (i % 8); /* Big-endian within qword */
            hw_aad[qw_idx] |= ((uint64_t)aad[i]) << (8 * byte_idx);
        }
    }
    
    pack_bytes_to_qwords_be_fixed(plaintext, plaintextSz, hw_pt, pt_qwords);
    
    // printf("  Input sizes: key=16 iv=12 aad=%u pt=%u\n", aadSz, plaintextSz);
    // printf("  Allocated buffers: aad=%u qwords, pt/ct=%u qwords\n", aad_qwords, pt_qwords);
    
    /* Reset and encrypt with hardware */
    hw_aes_gcm_reset(aes_gcmctrl);
    hw_aes_gcm_encrypt(aes_gcmctrl, hw_ct, hw_pt, plaintextSz,
                       hw_key, 16, hw_iv, 12, hw_aad, aadSz, hw_tag, 16);
    
    /* Convert results back to byte format */
    unpack_qwords_to_bytes_be(hw_ct, plaintextSz, ciphertext);
    unpack_qwords_to_bytes_be(hw_tag, 16, authTag);
    end_timing("Hardware AES-GCM Seal");
    /* Debug: Print encryption results */
    // print_hex_debug("Hardware Ciphertext", ciphertext, plaintextSz);
    // print_hex_debug("Hardware Auth tag", authTag, 16);
    
    /* Append auth tag */
    XMEMCPY(ciphertext + plaintextSz, authTag, 16);
    
    ret = 0; /* Success */

cleanup:
    /* Free dynamically allocated buffers */
    if (hw_aad != NULL) {
        XFREE(hw_aad, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (hw_pt != NULL) {
        XFREE(hw_pt, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (hw_ct != NULL) {
        XFREE(hw_ct, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    
    return ret;
}

/* Hardware AES-GCM Open Base with dynamic allocation */
static int hw_HpkeOpenBase(Hpke* hpke, void* receiverKey, 
                           const byte* ephemeralPubKey, word16 ephemeralPubKeySz,
                           const byte* info, word32 infoSz,
                           const byte* aad, word32 aadSz,
                           const byte* ciphertext, word32 ciphertextSz,
                           byte* plaintext)
{
    int ret;
    byte key[16];
    byte baseNonce[12];
    byte authTag[16];
    word32 plaintextSz;
    
    /* Hardware AES-GCM controller address */
    void* aes_gcmctrl = (void*)AES_GCM_HW_BASE_ADDR;
    
    /* Validation */
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
    
    /* Calculate required qwords dynamically */
    word32 aad_qwords = (aadSz + 7) / 8;
    word32 ct_qwords = (plaintextSz + 7) / 8;
    
    /* Static buffers for keys and tag */
    uint64_t hw_key[4] = {0};      /* AES-128 always uses 4 qwords */
    uint64_t hw_iv[2] = {0};       /* 12-byte nonce always uses 2 qwords */
    uint64_t hw_tag[2] = {0};      /* 16-byte auth tag always uses 2 qwords */
    
    /* Dynamically allocate AAD buffer */
    uint64_t* hw_aad = NULL;
    if (aadSz > 0) {
        hw_aad = XMALLOC(aad_qwords * sizeof(uint64_t), hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (hw_aad == NULL) {
            // printf("Failed to allocate AAD buffer (%u qwords)\n", aad_qwords);
            return MEMORY_E;
        }
        XMEMSET(hw_aad, 0, aad_qwords * sizeof(uint64_t));
    }
     
    /* Dynamically allocate ciphertext/plaintext buffers */
    uint64_t* hw_ct = XMALLOC(ct_qwords * sizeof(uint64_t), hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    uint64_t* hw_pt = XMALLOC(ct_qwords * sizeof(uint64_t), hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    
    if (hw_ct == NULL || hw_pt == NULL) {
        // printf("Failed to allocate ciphertext/plaintext buffers (%u qwords each)\n", ct_qwords);
        ret = MEMORY_E;
        goto cleanup;
    }
    
    XMEMSET(hw_ct, 0, ct_qwords * sizeof(uint64_t));
    XMEMSET(hw_pt, 0, ct_qwords * sizeof(uint64_t));
    
    /* Extract auth tag */
    XMEMCPY(authTag, ciphertext + plaintextSz, 16);

    /* Setup receiver context */
    ret = hw_HpkeSetupBaseReceiver(hpke, receiverKey, ephemeralPubKey, ephemeralPubKeySz,
                                   info, infoSz, key, baseNonce);
    if (ret != 0) {
        // printf("Setup Base Receiver failed: %d\n", ret);
        goto cleanup;
    }
    
    printf("Opening with AES-GCM using hardware acceleration\n");
    start_timing();
    /* Convert to hardware format */
    pack_bytes_to_qwords_be_fixed(key, 16, hw_key, 4);
    pack_bytes_to_qwords_be_fixed(baseNonce, 12, hw_iv, 2);
    
    /* Pack AAD if present */
    if (aad != NULL && aadSz > 0) {
        /* Manual byte-by-byte packing for consistency */
        for (word32 i = 0; i < aadSz; i++) {
            word32 qw_idx = i / 8;
            word32 byte_idx = 7 - (i % 8); /* Big-endian within qword */
            hw_aad[qw_idx] |= ((uint64_t)aad[i]) << (8 * byte_idx);
        }
    }
    
    pack_bytes_to_qwords_be_fixed(ciphertext, plaintextSz, hw_ct, ct_qwords);
    pack_bytes_to_qwords_be_fixed(authTag, 16, hw_tag, 2);
    
    // printf("  Input sizes: key=16 iv=12 aad=%u ct=%u\n", aadSz, plaintextSz);
    // printf("  Allocated buffers: aad=%u qwords, ct/pt=%u qwords\n", aad_qwords, ct_qwords);
    
    /* Reset and decrypt with hardware */
    hw_aes_gcm_reset(aes_gcmctrl);
    ret = hw_aes_gcm_decrypt_verify(aes_gcmctrl, hw_pt, hw_ct, plaintextSz,
                                    hw_key, 16, hw_iv, 12, hw_aad, aadSz, hw_tag, 16);
    
    if (ret != 0) {
        // printf("Hardware AES-GCM decryption/verification failed: %d\n", ret);
        if (ret == -6) {
            // printf("Authentication tag verification failed\n");
        }
        goto cleanup;
    }
    
    /* Convert result back to byte format */
    unpack_qwords_to_bytes_be(hw_pt, plaintextSz, plaintext);

    /* Debug: Print decryption result */
    // print_hex_debug("Hardware Decrypted plaintext", plaintext, plaintextSz);
    // printf("=== HPKE Open Base (Hardware) Completed Successfully ===\n");
    end_timing("Hardware AES-GCM Open");
    ret = 0; /* Success */

cleanup:
    /* Free dynamically allocated buffers */
    if (hw_aad != NULL) {
        XFREE(hw_aad, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (hw_ct != NULL) {
        XFREE(hw_ct, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (hw_pt != NULL) {
        XFREE(hw_pt, hpke->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    
    return ret;
}


/* Hardware-accelerated key generation */
static int hw_curve25519_make_key(WC_RNG* rng, int keysize, curve25519_key* key)
{
    int ret;
    static const byte kCurve25519BasePoint[CURVE25519_KEYSIZE] = {9};

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    // printf("    === Key Generation Process ===\n");

    /* Generate random private key */
    ret = wc_curve25519_make_priv(rng, keysize, key->k);    
    if (ret != 0) {
        // printf("    Private key generation failed: %d\n", ret);
        return ret;
    }

    key->privSet = 1;
    // printf("    Private key generated successfully\n");
    // print_hex_debug("Generated private key", key->k, CURVE25519_KEYSIZE);
    
    /* Print base point for reference */
    // print_hex_debug("Base point", kCurve25519BasePoint, CURVE25519_KEYSIZE);
    
    /* Use HARDWARE to compute public key: public = private * basepoint */
    // printf("    Computing public key with hardware: public = private * basepoint\n");
    // start_timing();
    ret = hw_curve25519_scalar_mult(key->p.point, key->k, kCurve25519BasePoint);
    // end_timing("Hardware public key generation");
    
    if (ret == 0) {
        key->pubSet = 1;
        // printf("    Public key computed successfully\n");
        // print_hex_debug("Computed public key", key->p.point, CURVE25519_KEYSIZE);
        ret = wc_curve25519_set_rng(key, rng);
    } else {
        // printf("    Hardware public key computation failed: %d\n", ret);
    }
    
    // printf("    === Key Generation Complete ===\n");
    return ret;
}

/* Hardware-accelerated HPKE key pair generation */
static int hw_HpkeGenerateKeyPair(Hpke* hpke, void** keypair, WC_RNG* rng)
{
    int ret = 0;

    if (hpke == NULL || keypair == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    if (hpke->kem != DHKEM_X25519_HKDF_SHA256)
        return BAD_FUNC_ARG;

    // printf("  === HPKE Key Pair Generation ===\n");

    *keypair = XMALLOC(sizeof(curve25519_key), hpke->heap, DYNAMIC_TYPE_CURVE25519);
    if (*keypair != NULL) {
        ret = wc_curve25519_init_ex((curve25519_key*)*keypair, hpke->heap, INVALID_DEVID);
        if (ret == 0) {
            // printf("  Key structure initialized, generating key pair...\n");
            /* Use hardware-accelerated key generation */
            ret = hw_curve25519_make_key(rng, 32, (curve25519_key*)*keypair);
            
            if (ret == 0) {
                // printf("  Key pair generation successful!\n");
                // print_key_debug("Generated Key Pair", (curve25519_key*)*keypair);
            } else {
                // printf("  Key pair generation failed: %d\n", ret);
            }
        } else {
            // printf("  Key structure initialization failed: %d\n", ret);
        }
    } else {
        // printf("  Memory allocation failed\n");
        ret = MEMORY_E;
    }

    if (ret != 0 && *keypair != NULL) {
        wc_HpkeFreeKey(hpke, (word16)hpke->kem, *keypair, hpke->heap);
        *keypair = NULL;
    }

    // printf("  === HPKE Key Pair Generation Complete ===\n");
    return ret;
}

/* Modified test function using static buffers */
static int test_hpke_large_data_static(void)
{
    printf("\n=== HPKE Large Data Test (Static Buffers) ===\n");
    
    int ret = 0;
    Hpke hpke;
    WC_RNG rng;
    void* receiverKey = NULL;
    void* ephemeralKey = NULL;
    
    /* Use static buffers - NO malloc() calls */
    const word32 plaintext_len = HPKE_TEST_BYTES;  // 1KB
    const word32 aad_len = 32;                     // 32 bytes
    const char* info_str = "Large static data test";
    word32 info_len = strlen(info_str);
    
    /* Point to static buffers */
    byte* plaintext = hpke_plaintext_buf;
    byte* aad = hpke_aad_buf;
    byte* ciphertext = hpke_ciphertext_buf;
    byte* decrypted = hpke_decrypted_buf;
    
    printf("Using static buffers: %u-byte plaintext, %u-byte AAD\n", 
           plaintext_len, aad_len);
    
    /* Fill with test data */
    for (word32 i = 0; i < plaintext_len; i++) {
        plaintext[i] = (byte)(i & 0xFF);
    }
    for (word32 i = 0; i < aad_len; i++) {
        aad[i] = (byte)((i + 0x55) & 0xFF);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    if (ret != 0) {
        printf("RNG init failed: %d\n", ret);
        goto cleanup_rng;
    }
    
    /* Initialize HPKE */
    ret = wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, HPKE_AES_128_GCM, g_heap_hint);
    if (ret != 0) {
        printf("HPKE init failed: %d\n", ret);
        goto cleanup_rng;
    }
    
    /* Generate keys */
    printf("Generating receiver key...\n");
    ret = hw_HpkeGenerateKeyPair(&hpke, &receiverKey, &rng);
    if (ret != 0) {
        printf("Receiver key generation failed: %d\n", ret);
        goto cleanup_rng;
    }

    printf("Generating ephemeral key...\n");
    ret = hw_HpkeGenerateKeyPair(&hpke, &ephemeralKey, &rng);
    if (ret != 0) {
        printf("Ephemeral key generation failed: %d\n", ret);
        goto cleanup_keys;
    }
    
    /* Get ephemeral public key */
    byte ephemeral_pk[32];
    word16 ephemeral_pk_size = sizeof(ephemeral_pk);
    ret = wc_HpkeSerializePublicKey(&hpke, ephemeralKey, ephemeral_pk, &ephemeral_pk_size);
    if (ret != 0) {
        printf("Public key serialization failed: %d\n", ret);
        goto cleanup_keys;
    }
    
    printf("Testing with %u-byte plaintext and %u-byte AAD\n", plaintext_len, aad_len);
    
    /* Seal */
    printf("Sealing...\n");
    start_timing();
    ret = hw_HpkeSealBase(&hpke, ephemeralKey, receiverKey,
                          (const byte*)info_str, info_len,
                          aad, aad_len,
                          plaintext, plaintext_len,
                          ciphertext);
    end_timing("Large data seal operation");
    
    if (ret != 0) {
        printf("Seal failed: %d\n", ret);
        goto cleanup_keys;
    }
    
    /* Open */
    printf("Opening...\n");
    start_timing();
    ret = hw_HpkeOpenBase(&hpke, receiverKey, ephemeral_pk, ephemeral_pk_size,
                          (const byte*)info_str, info_len,
                          aad, aad_len,
                          ciphertext, plaintext_len + 16,
                          decrypted);
    end_timing("Large data open operation");
    
    if (ret != 0) {
        printf("Open failed: %d\n", ret);
        goto cleanup_keys;
    }
    
    /* Verify */
    printf("Verifying...\n");
    if (XMEMCMP(plaintext, decrypted, plaintext_len) == 0) {
        printf("SUCCESS: Large data HPKE round-trip completed!\n");
        printf("✅ Static buffers working correctly\n");
        printf("✅ Processed %u bytes plaintext + %u bytes AAD\n", plaintext_len, aad_len);
    } else {
        printf("FAIL: Decrypted data doesn't match\n");
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
    
    return ret;
}

/* Create Ascon context with proper heap hint */
static wc_AsconAEAD128* create_ascon_context(void)
{
    /* Standard WolfSSL creation often fails, so use manual allocation */
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

/* Simple Ascon-128 encrypt/decrypt test */
static int test_ascon_basic(void)
{
    printf("\n=== Ascon-128 Basic Test ===\n");
    
    int ret;
    wc_AsconAEAD128* asconAEAD = NULL;
    
    /* Test vectors */
    const byte key[ASCON_AEAD128_KEY_SZ] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    const byte nonce[ASCON_AEAD128_NONCE_SZ] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    const char* plaintext_str = "Hello, Ascon-128! This is a test message.";
    word32 plaintext_len = strlen(plaintext_str);
    
    const char* aad_str = "Additional authenticated data";
    word32 aad_len = strlen(aad_str);
    
    /* Buffers */
    byte ciphertext[128];
    byte tag[ASCON_AEAD128_TAG_SZ];
    byte decrypted[128];
    
    printf("📋 Test Parameters:\n");
    printf("   Plaintext: \"%s\" (%u bytes)\n", plaintext_str, plaintext_len);
    printf("   AAD: \"%s\" (%u bytes)\n", aad_str, aad_len);
    printf("   Key size: %d bytes, Nonce size: %d bytes, Tag size: %d bytes\n", 
           ASCON_AEAD128_KEY_SZ, ASCON_AEAD128_NONCE_SZ, ASCON_AEAD128_TAG_SZ);
    
    /* Create Ascon context */
    asconAEAD = create_ascon_context();
    if (asconAEAD == NULL) {
        printf("❌ Failed to create Ascon context\n");
        return -1;
    }
    printf("✅ Ascon context created\n");
    
    /* ENCRYPTION PHASE */
    printf("\n🔒 Encryption:\n");
    
    ret = wc_AsconAEAD128_SetKey(asconAEAD, key);
    if (ret != 0) { printf("❌ SetKey failed: %d\n", ret); goto cleanup; }
    
    ret = wc_AsconAEAD128_SetNonce(asconAEAD, nonce);
    if (ret != 0) { printf("❌ SetNonce failed: %d\n", ret); goto cleanup; }
    
    ret = wc_AsconAEAD128_SetAD(asconAEAD, (const byte*)aad_str, aad_len);
    if (ret != 0) { printf("❌ SetAD failed: %d\n", ret); goto cleanup; }
    
    ret = wc_AsconAEAD128_EncryptUpdate(asconAEAD, ciphertext, (const byte*)plaintext_str, plaintext_len);
    if (ret != 0) { printf("❌ EncryptUpdate failed: %d\n", ret); goto cleanup; }
    
    ret = wc_AsconAEAD128_EncryptFinal(asconAEAD, tag);
    if (ret != 0) { printf("❌ EncryptFinal failed: %d\n", ret); goto cleanup; }
    
    printf("   ✅ Encryption successful\n");
    
    /* DECRYPTION PHASE */
    printf("\n🔓 Decryption:\n");
    
    /* Clear context and reinitialize for decryption */
    wc_AsconAEAD128_Clear(asconAEAD);
    ret = wc_AsconAEAD128_Init(asconAEAD);
    if (ret != 0) { printf("❌ Re-init failed: %d\n", ret); goto cleanup; }
    
    ret = wc_AsconAEAD128_SetKey(asconAEAD, key);
    if (ret != 0) { printf("❌ SetKey (decrypt) failed: %d\n", ret); goto cleanup; }
    
    ret = wc_AsconAEAD128_SetNonce(asconAEAD, nonce);
    if (ret != 0) { printf("❌ SetNonce (decrypt) failed: %d\n", ret); goto cleanup; }
    
    ret = wc_AsconAEAD128_SetAD(asconAEAD, (const byte*)aad_str, aad_len);
    if (ret != 0) { printf("❌ SetAD (decrypt) failed: %d\n", ret); goto cleanup; }
    
    ret = wc_AsconAEAD128_DecryptUpdate(asconAEAD, decrypted, ciphertext, plaintext_len);
    if (ret != 0) { printf("❌ DecryptUpdate failed: %d\n", ret); goto cleanup; }
    
    ret = wc_AsconAEAD128_DecryptFinal(asconAEAD, tag);
    if (ret != 0) {
        printf("❌ DecryptFinal failed: %d\n", ret);
        printf("   → Authentication verification failed\n");
        goto cleanup;
    }
    
    printf("   ✅ Decryption successful\n");
    
    /* VERIFICATION */
    printf("\n✅ Verification:\n");
    decrypted[plaintext_len] = '\0';
    printf("   Original:  \"%s\"\n", plaintext_str);
    printf("   Decrypted: \"%s\"\n", (char*)decrypted);
    
    if (memcmp(plaintext_str, decrypted, plaintext_len) == 0) {
        printf("🎉 SUCCESS: Ascon-128 working perfectly!\n");
        ret = 0;
    } else {
        printf("❌ FAILURE: Data mismatch\n");
        ret = -1;
    }
    
cleanup:
    free_ascon_context(asconAEAD);
    return ret;
}

/* Ascon-128 Large Data Test (1KB) using static buffers */
static int test_ascon_large_data_static(void)
{
    printf("\n=== Ascon-128 Large Data Test (Static Buffers - 1KB) ===\n");
    
    int ret;
    wc_AsconAEAD128* asconAEAD = NULL;
    
    /* Test vectors */
    const byte key[ASCON_AEAD128_KEY_SZ] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    const byte nonce[ASCON_AEAD128_NONCE_SZ] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    /* Use same size as HPKE test */
    const word32 plaintext_len = HPKE_TEST_BYTES;  // 1KB
    const word32 aad_len = 256;                    // 256 bytes AAD
    
    /* Use the same static buffers as HPKE test */
    byte* plaintext = hpke_plaintext_buf;      // 1KB static buffer
    byte* aad = hpke_aad_buf;                  // 256 bytes AAD buffer
    byte* ciphertext = hpke_ciphertext_buf;    // 1KB + 16 bytes for tag
    byte* decrypted = hpke_decrypted_buf;      // 1KB for decrypted data
    
    byte tag[ASCON_AEAD128_TAG_SZ];
    
    printf("📋 Large Data Test Parameters:\n");
    printf("   Plaintext size: %u bytes (1KB)\n", plaintext_len);
    printf("   AAD size: %u bytes\n", aad_len);
    printf("   Key size: %d bytes, Nonce size: %d bytes, Tag size: %d bytes\n", 
           ASCON_AEAD128_KEY_SZ, ASCON_AEAD128_NONCE_SZ, ASCON_AEAD128_TAG_SZ);
    printf("   Using static buffers (no dynamic allocation)\n");
    
    /* Fill static buffers with test data (same pattern as HPKE test) */
    printf("🔧 Filling static buffers with test data...\n");
    for (word32 i = 0; i < plaintext_len; i++) {
        plaintext[i] = (byte)(i & 0xFF);  // Repeating 0x00-0xFF pattern
    }
    for (word32 i = 0; i < aad_len; i++) {
        aad[i] = (byte)((i + 0x55) & 0xFF);  // Repeating pattern starting from 0x55
    }
    
    printf("   ✅ Test data generated: %u-byte plaintext, %u-byte AAD\n", 
           plaintext_len, aad_len);
    
    /* Create Ascon context */
    printf("\n🔧 Creating Ascon context...\n");
    asconAEAD = create_ascon_context();
    if (asconAEAD == NULL) {
        printf("❌ Failed to create Ascon context\n");
        return -1;
    }
    printf("✅ Ascon context created for large data processing\n");
    
    /* ENCRYPTION PHASE */
    printf("\n🔒 Large Data Encryption (1KB):\n");
    
    start_timing();
    
    ret = wc_AsconAEAD128_SetKey(asconAEAD, key);
    if (ret != 0) { 
        printf("❌ SetKey failed: %d\n", ret); 
        goto cleanup; 
    }
    
    ret = wc_AsconAEAD128_SetNonce(asconAEAD, nonce);
    if (ret != 0) { 
        printf("❌ SetNonce failed: %d\n", ret); 
        goto cleanup; 
    }
    
    ret = wc_AsconAEAD128_SetAD(asconAEAD, aad, aad_len);
    if (ret != 0) { 
        printf("❌ SetAD failed: %d\n", ret); 
        goto cleanup; 
    }
    
    /* Process large plaintext */
    ret = wc_AsconAEAD128_EncryptUpdate(asconAEAD, ciphertext, plaintext, plaintext_len);
    if (ret != 0) { 
        printf("❌ EncryptUpdate failed: %d\n", ret); 
        goto cleanup; 
    }
    
    ret = wc_AsconAEAD128_EncryptFinal(asconAEAD, tag);
    if (ret != 0) { 
        printf("❌ EncryptFinal failed: %d\n", ret); 
        goto cleanup; 
    }
    
    end_timing("Ascon-128 Large Data Encryption (1KB)");
    
    printf("   ✅ Large data encryption successful!\n");
    printf("   ✅ Processed %u bytes plaintext + %u bytes AAD\n", plaintext_len, aad_len);
    printf("   ✅ Generated %u-byte authentication tag\n", ASCON_AEAD128_TAG_SZ);
    
    /* Clear context and prepare for decryption */
    printf("\n🔧 Preparing for decryption...\n");
    wc_AsconAEAD128_Clear(asconAEAD);
    ret = wc_AsconAEAD128_Init(asconAEAD);
    if (ret != 0) { 
        printf("❌ Re-init failed: %d\n", ret); 
        goto cleanup; 
    }
    
    /* DECRYPTION PHASE */
    printf("\n🔓 Large Data Decryption (1KB):\n");
    
    start_timing();
    
    ret = wc_AsconAEAD128_SetKey(asconAEAD, key);
    if (ret != 0) { 
        printf("❌ SetKey (decrypt) failed: %d\n", ret); 
        goto cleanup; 
    }
    
    ret = wc_AsconAEAD128_SetNonce(asconAEAD, nonce);
    if (ret != 0) { 
        printf("❌ SetNonce (decrypt) failed: %d\n", ret); 
        goto cleanup; 
    }
    
    ret = wc_AsconAEAD128_SetAD(asconAEAD, aad, aad_len);
    if (ret != 0) { 
        printf("❌ SetAD (decrypt) failed: %d\n", ret); 
        goto cleanup; 
    }
    
    /* Process large ciphertext */
    ret = wc_AsconAEAD128_DecryptUpdate(asconAEAD, decrypted, ciphertext, plaintext_len);
    if (ret != 0) { 
        printf("❌ DecryptUpdate failed: %d\n", ret); 
        goto cleanup; 
    }
    
    ret = wc_AsconAEAD128_DecryptFinal(asconAEAD, tag);
    if (ret != 0) {
        printf("❌ DecryptFinal failed: %d\n", ret);
        printf("   → Authentication verification failed for large data\n");
        goto cleanup;
    }
    
    end_timing("Ascon-128 Large Data Decryption (1KB)");
    
    printf("   ✅ Large data decryption successful!\n");
    printf("   ✅ Authentication tag verified for 1KB data + 256B AAD\n");
    
    /* VERIFICATION */
    printf("\n✅ Large Data Verification:\n");
    
    printf("   Verifying %u-byte data integrity...\n", plaintext_len);
    if (XMEMCMP(plaintext, decrypted, plaintext_len) == 0) {
        printf("🎉 SUCCESS: Ascon-128 large data test completed perfectly!\n");
        printf("   ✅ All %u bytes verified correctly\n", plaintext_len);
        printf("   ✅ Static buffer management working\n");
        printf("   ✅ Large data processing capability confirmed\n");
        printf("   ✅ Authentication working for large payloads\n");
        
        /* Show first and last few bytes for verification */
        printf("   📊 Data verification samples:\n");
        printf("      First 16 bytes - Original: ");
        for (int i = 0; i < 16; i++) printf("%02x", plaintext[i]);
        printf("\n");
        printf("      First 16 bytes - Decrypted: ");
        for (int i = 0; i < 16; i++) printf("%02x", decrypted[i]);
        printf("\n");
        
        printf("      Last 16 bytes  - Original: ");
        for (int i = plaintext_len - 16; i < plaintext_len; i++) printf("%02x", plaintext[i]);
        printf("\n");
        printf("      Last 16 bytes  - Decrypted: ");
        for (int i = plaintext_len - 16; i < plaintext_len; i++) printf("%02x", decrypted[i]);
        printf("\n");
        
        ret = 0;
    } else {
        printf("❌ FAILURE: Large data mismatch detected!\n");
        
        /* Find first mismatch */
        for (word32 i = 0; i < plaintext_len; i++) {
            if (plaintext[i] != decrypted[i]) {
                printf("   First mismatch at byte %u: expected 0x%02x, got 0x%02x\n", 
                       i, plaintext[i], decrypted[i]);
                break;
            }
        }
        ret = -1;
    }
    
cleanup:
    free_ascon_context(asconAEAD);
    
    /* Clear sensitive data from static buffers */
    XMEMSET(hpke_plaintext_buf, 0, HPKE_TEST_BYTES);
    XMEMSET(hpke_aad_buf, 0, 256);
    XMEMSET(hpke_ciphertext_buf, 0, HPKE_TEST_BYTES + 16);
    XMEMSET(hpke_decrypted_buf, 0, HPKE_TEST_BYTES);
    
    printf("   🧹 Static buffers cleared\n");
    
    return ret;
}

/* ============================================================================
 * AES-GCM PERFORMANCE TEST
 * ============================================================================ */

/* Performance test for AES-GCM encryption and decryption (128 bytes) */
static int test_aes_gcm_performance_128bytes(void)
{
    printf("\n=== AES-GCM Performance Test (64 bytes) ===\n");
    
    int ret = 0;
    unsigned long start_cycles, end_cycles;
    void* aes_gcmctrl = (void*)AES_GCM_HW_BASE_ADDR;
    
    /* Test data - byte format */
    #define AES_TEST_SIZE 64
    byte key[16];  /* AES-128 key */
    byte nonce[12];  /* GCM nonce */
    byte aad[16];
    byte plaintext[AES_TEST_SIZE];
    byte ciphertext[AES_TEST_SIZE];
    byte decrypted[AES_TEST_SIZE];
    byte tag[16];
    
    /* Hardware format - qword arrays */
    uint64_t hw_key[4];      /* 16 bytes = 2 qwords, but allocate 4 for safety */
    uint64_t hw_nonce[2];    /* 12 bytes = 2 qwords */
    uint64_t hw_aad[2];      /* 16 bytes = 2 qwords */
    uint64_t hw_pt[8];       /* 64 bytes = 8 qwords */
    uint64_t hw_ct[8];       /* 64 bytes = 8 qwords */
    uint64_t hw_decrypted[8]; /* 64 bytes = 8 qwords */
    uint64_t hw_tag[2];      /* 16 bytes = 2 qwords */
    
    /* Clear hardware buffers */
    XMEMSET(hw_key, 0, sizeof(hw_key));
    XMEMSET(hw_nonce, 0, sizeof(hw_nonce));
    XMEMSET(hw_aad, 0, sizeof(hw_aad));
    XMEMSET(hw_pt, 0, sizeof(hw_pt));
    XMEMSET(hw_ct, 0, sizeof(hw_ct));
    XMEMSET(hw_decrypted, 0, sizeof(hw_decrypted));
    XMEMSET(hw_tag, 0, sizeof(hw_tag));
    
    /* Fill test data with patterns */
    for (int i = 0; i < 16; i++) {
        key[i] = (byte)(i * 0x11);
    }
    for (int i = 0; i < 12; i++) {
        nonce[i] = (byte)(i * 0x22);
    }
    for (int i = 0; i < 16; i++) {
        aad[i] = (byte)((i + 0x55) & 0xFF);
    }
    for (int i = 0; i < AES_TEST_SIZE; i++) {
        plaintext[i] = (byte)(i & 0xFF);
    }
    
    printf("\n--- Test Setup ---\n");
    printf("Key (16 bytes):   ");
    for (int i = 0; i < 16; i++) printf("%02x", key[i]);
    printf("\n");
    
    printf("Nonce (12 bytes): ");
    for (int i = 0; i < 12; i++) printf("%02x", nonce[i]);
    printf("\n");
    
    printf("AAD (16 bytes):   ");
    for (int i = 0; i < 16; i++) printf("%02x", aad[i]);
    printf("\n");
    
    printf("Plaintext (first 32 bytes): ");
    for (int i = 0; i < 32; i++) printf("%02x", plaintext[i]);
    printf("\n");
    
    /* Convert byte arrays to hardware qword format (big-endian) */
    pack_bytes_to_qwords_be_fixed(key, 16, hw_key, 4);
    pack_bytes_to_qwords_be_fixed(nonce, 12, hw_nonce, 2);
    pack_bytes_to_qwords_be_fixed(aad, 16, hw_aad, 2);
    pack_bytes_to_qwords_be_fixed(plaintext, AES_TEST_SIZE, hw_pt, 8);
    
    /* Test AES-GCM Encryption */
    printf("\n--- Testing AES-GCM Encryption (64 bytes) ---\n");
    
    hw_aes_gcm_reset(aes_gcmctrl);
    
    start_cycles = rdcycle();
    
    hw_aes_gcm_encrypt(aes_gcmctrl, hw_ct, hw_pt, AES_TEST_SIZE,
                       hw_key, 16, hw_nonce, 12, hw_aad, 16, hw_tag, 16);
    
    end_cycles = rdcycle();
    
    unsigned long encrypt_cycles = end_cycles - start_cycles;
    printf("✅ AES-GCM Encryption (64 bytes): %lu cycles\n", encrypt_cycles);
    
    /* Convert results back to byte format */
    unpack_qwords_to_bytes_be(hw_ct, AES_TEST_SIZE, ciphertext);
    unpack_qwords_to_bytes_be(hw_tag, 16, tag);
    
    printf("Ciphertext (first 32 bytes): ");
    for (int i = 0; i < 32; i++) printf("%02x", ciphertext[i]);
    printf("\n");
    
    printf("Authentication Tag: ");
    for (int i = 0; i < 16; i++) printf("%02x", tag[i]);
    printf("\n");
    
    /* Test AES-GCM Decryption */
    printf("\n--- Testing AES-GCM Decryption (64 bytes) ---\n");
    
    hw_aes_gcm_reset(aes_gcmctrl);
    
    start_cycles = rdcycle();
    
    ret = hw_aes_gcm_decrypt_verify(aes_gcmctrl, hw_decrypted, hw_ct, AES_TEST_SIZE,
                                    hw_key, 16, hw_nonce, 12, hw_aad, 16, hw_tag, 16);
    
    end_cycles = rdcycle();
    
    if (ret != 0) {
        printf("❌ AES-GCM decryption/verification failed: %d\n", ret);
        return ret;
    }
    
    unsigned long decrypt_cycles = end_cycles - start_cycles;
    printf("✅ AES-GCM Decryption (64 bytes): %lu cycles\n", decrypt_cycles);
    
    /* Convert result back to byte format */
    unpack_qwords_to_bytes_be(hw_decrypted, AES_TEST_SIZE, decrypted);
    
    printf("Decrypted (first 32 bytes): ");
    for (int i = 0; i < 32; i++) printf("%02x", decrypted[i]);
    printf("\n");
    
    /* Verify plaintext matches */
    printf("\n--- Verification ---\n");
    if (XMEMCMP(plaintext, decrypted, AES_TEST_SIZE) != 0) {
        printf("❌ Decrypted plaintext doesn't match original!\n");
        
        /* Find first mismatch */
        for (int i = 0; i < AES_TEST_SIZE; i++) {
            if (plaintext[i] != decrypted[i]) {
                printf("First mismatch at byte %d: original=0x%02x decrypted=0x%02x\n", 
                       i, plaintext[i], decrypted[i]);
                break;
            }
        }
        return -1;
    }
    
    printf("✅ Plaintext verified successfully\n");
    
    /* Performance Summary */
    printf("\n=== AES-GCM Performance Summary ===\n");
    printf("Encryption (64 bytes): %lu cycles\n", encrypt_cycles);
    printf("Decryption (64 bytes): %lu cycles\n", decrypt_cycles);
    printf("Total:                 %lu cycles\n", encrypt_cycles + decrypt_cycles);
    printf("===================================\n");
    
    return 0;
}


/* Updated main function to test seal/open only */
int main(void)
{
    // test_gcm_compare_tc2((void*)AES_GCM_HW_BASE_ADDR);

    // printf("HPKE Seal/Open Test (Bypass Key Generation)\n");
    // printf("===========================================\n");


    /* Setup */
    if (setup_wolfssl_memory() != 0) {
        printf("FAIL: Static memory setup failed\n");
        return -1;
    }
    
    /* Test: AES-GCM Performance (128 bytes) */
    printf("\n[Test: AES-GCM Performance]\n");
    int aes_gcm_result = test_aes_gcm_performance_128bytes();
    
    if (aes_gcm_result == 0) {
        printf("✅ AES-GCM Performance Test PASSED\n");
    } else {
        printf("❌ AES-GCM Performance Test FAILED\n");
    }

    int basic_result = test_hpke_large_data_static();
    // int tamper_result = test_ascon_tamper_detection();
    
    printf("\n📊 Ascon Test Results:\n");
    printf("   Basic AEAD test: %s\n", basic_result == 0 ? "✅ PASS" : "❌ FAIL");
    // printf("   Tamper detection: %s\n", tamper_result == 0 ? "✅ PASS" : "❌ FAIL");


    
    // printf("✅ WolfSSL memory setup complete\n");
    
    
    // /* Test 1: Direct AES-GCM with your exact derived values */
    // printf("\n🔧 Test 1: Direct AES-GCM with exact derived values\n");
    // int test1_result = test_direct_aes_gcm_with_expected_values();
    
    /* Test 2: Full Seal/Open with mock keys */
    // printf("\n🔒 Test 2: Full Seal/Open with mock keys\n");
    // int test2_result = test_hpke_proper_hardware();
    
    /* Test 3: Large data seal/open with dynamic allocation */
    // printf("\n📦 Test 3: Large data seal/open (dynamic allocation)\n");
    // int test3_result = test_hpke_large_data_static();
    
    /* Test 4: Large data seal/open with static buffers */
    // printf("\n📦 Test 4: Large data seal/open (static buffers)\n");
    // uintptr_t hmac_sha_reg= 0x64005000;
    // hwhmacsha_test_hkdf_expand_65bytes((void*)hmac_sha_reg);
    
    /* Summary */



    return 0;
}
