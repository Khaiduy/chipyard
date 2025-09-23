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
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/aes.h>
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

#ifndef XMALLOC
#define XMALLOC(sz, heap, type) malloc(sz)
#endif

#ifndef XFREE
#define XFREE(ptr, heap, type) free(ptr)
#endif

/* Hardware accelerator base addresses */
#define X25519_HW_BASE_ADDR  0x64004000
#define AES_GCM_HW_BASE_ADDR 0x64009000
#define HMAC_SHA_HW_BASE_ADDR 0x64005000

#define SHA256_MODE 1

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
    // printf("    HKDF Extract step\n");
    // start_timing();
    ret = hw_HKDF_Extract(NULL, 0,  /* No salt */
                          dh, dhSz, 
                          prkExtract);
    // end_timing("HKDF Extract");
    
    if (ret != 0) {
        // printf("    HKDF Extract failed: %d\n", ret);
        return ret;
    }
    
    /* Step 2: Expand */
    // printf("    HKDF Expand step\n");
    // start_timing();
    ret = hw_HKDF_Expand(prkExtract, sizeof(prkExtract),
                         kemContext, kemContextSz,
                         sharedSecret, CURVE25519_KEYSIZE);
    // end_timing("HKDF Expand");
    
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
    // start_timing();
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
    // start_timing();
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
    // start_timing();
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
    ret = hw_HpkeEncap(hpke, ephemeralKey, receiverKey, sharedSecret);
    if (ret != 0) {
        // printf("Encapsulation failed: %d\n", ret);
        return ret;
    }
    
    /* Step 2: Key Schedule */
    // printf("Step 2: Key Schedule\n");
    ret = hw_HpkeKeyScheduleBase(hpke, sharedSecret, info, infoSz, key, baseNonce);
    if (ret != 0) {
        // printf("Key Schedule failed: %d\n", ret);
        return ret;
    }
    
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
    // printf("Step 1: DH operation\n");
    // start_timing();
    ret = hw_curve25519_scalar_mult(sharedSecret, recvKey->k, ephemeralPubKey);
    // end_timing("Hardware DH operation");
    
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
    
    /* Step 3: Key Schedule */
    // printf("Step 3: Key Schedule\n");
    ret = hw_HpkeKeyScheduleBase(hpke, extractedSecret, info, infoSz, key, baseNonce);
    if (ret != 0) {
        // printf("Key Schedule failed: %d\n", ret);
        return ret;
    }
    
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


#define HPKE_TEST_BYTES (1 * 1024)  // 128 bytes test size

#define HPKE_TEST_WORDS64 ((HPKE_TEST_BYTES + 7) / 8)  // Convert to qwords


/* Static buffers for HPKE large data test */
static byte hpke_plaintext_buf[HPKE_TEST_BYTES];     // 1KB
static byte hpke_aad_buf[256];                       // 256 bytes AAD
static byte hpke_ciphertext_buf[HPKE_TEST_BYTES + 16]; // 1KB + 16-byte tag
static byte hpke_decrypted_buf[HPKE_TEST_BYTES];     // 1KB

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
    
    // printf("✅ WolfSSL memory setup complete\n");
    
    
    // /* Test 1: Direct AES-GCM with your exact derived values */
    // printf("\n🔧 Test 1: Direct AES-GCM with exact derived values\n");
    // int test1_result = test_direct_aes_gcm_with_expected_values();
    
    /* Test 2: Full Seal/Open with mock keys */
    // printf("\n🔒 Test 2: Full Seal/Open with mock keys\n");
    // int test2_result = test_hpke_proper_hardware();
    
    /* Test 3: Large data seal/open with dynamic allocation */
    // printf("\n📦 Test 3: Large data seal/open (dynamic allocation)\n");
    int test3_result = test_hpke_large_data_static();
    
    /* Test 4: Large data seal/open with static buffers */
    // printf("\n📦 Test 4: Large data seal/open (static buffers)\n");
    // uintptr_t hmac_sha_reg= 0x64005000;
    // hwhmacsha_test_hkdf_expand_65bytes((void*)hmac_sha_reg);
    
    /* Summary */



    return 0;
}

// /* Enhanced test case comparing hardware vs WolfSSL for 65-byte HKDF Expand */
// void hwhmacsha_test_hkdf_expand_65bytes(void *hmac_shactrl)
// {
//     // printf("\n=== HKDF Expand Comparison: Hardware vs WolfSSL (65 bytes) ===\n");
//     // printf("Testing message: T(0) + KEM_context(64) + counter(1) = 65 bytes\n");
    
//     /* Test data setup */
//     unsigned char hkdf_msg[65];
//     unsigned char prk_key[32];
//     unsigned char info_context[64];  /* KEM context separate for WolfSSL */
//     int offset = 0;
    
//     /* Build 32-byte PRK (simulated) */
//     for (int i = 0; i < 32; i++) {
//         prk_key[i] = 0x77;  /* Consistent PRK for both tests */
//     }
//     printf("Using 32-byte PRK filled with 0x77\n");
    
//     /* Build 64-byte KEM context */
//     printf("Building 64-byte KEM context...\n");
//     for (int i = 0; i < 32; i++) {
//         info_context[i] = 0x11 + i;  /* Ephemeral public key simulation */
//         hkdf_msg[offset + i] = info_context[i];
//     }
//     offset += 32;
    
//     for (int i = 0; i < 32; i++) {
//         info_context[32 + i] = 0x33 + i;  /* Receiver public key simulation */
//         hkdf_msg[offset + i] = info_context[32 + i];
//     }
//     offset += 32;
    
//     /* Add counter byte */
//     hkdf_msg[offset] = 0x01;  /* Counter for iteration 1 */
//     offset += 1;
    
//     // printf("Total message length: %d bytes\n", offset);
//     // printf("KEM context: 64 bytes, Counter: 1 byte\n");


//     /* ========================================= */
//     /* HARDWARE HKDF EXPAND TEST                */
//     /* ========================================= */
//     printf("\n--- Hardware HKDF Expand (via hmacsha_compute) ---\n");
    
//     /* Convert to Vietnamese pattern for hardware */
//     uint64_t key_hkdf[8] = {0};
//     uint64_t msg_hkdf[32] = {0};
//     uint64_t mac_hkdf[8];
    
//     /* Pack PRK as key */
//     for (int i = 0; i < 32; i++) {
//         int qw_idx = i / 4;
//         int byte_idx = 3 - (i % 4);
//         if (qw_idx < 8) {
//             key_hkdf[qw_idx] |= ((uint64_t)prk_key[i]) << (8 * byte_idx);
//         }
//     }
    
//     /* Pack complete HKDF message (info + counter) */
//     for (int i = 0; i < 65; i++) {
//         int qw_idx = i / 4;
//         int byte_idx = 3 - (i % 4);
//         if (qw_idx < 32) {
//             msg_hkdf[qw_idx] |= ((uint64_t)hkdf_msg[i]) << (8 * byte_idx);
//         }
//     }
    
//     // printf("Hardware message structure:\n");
//     // printf("  Bytes 0-31:  Ephemeral public key\n");
//     // printf("  Bytes 32-63: Receiver public key\n");
//     // printf("  Byte 64:     Counter (0x01)\n");
    
//     /* Execute hardware HMAC */

//     // printf("key_hkdf (PRK) - Full 64-bit values:\n");
//     // for (int i = 0; i < 8; i++) {
//     //     printf("  key_hkdf[%d] = 0x%016llx\n", i, key_hkdf[i]);
//     // }

//     // printf("msg_hkdf (Info + Counter) - Full 64-bit values:\n");
//     // for (int i = 0; i < 32; i++) {
//     //     if (msg_hkdf[i] != 0) {  /* Only print non-zero values */
//     //         printf("  msg_hkdf[%d] = 0x%016llx\n", i, msg_hkdf[i]);
//     //     }
//     // }

//     start_timing();
//     int hardware_result = hmacsha_compute(hmac_shactrl, 
//                                         SHA256_MODE,
//                                         key_hkdf,
//                                         msg_hkdf,
//                                         65 * 8,        /* 520 bits */
//                                         mac_hkdf);
//     end_timing("Hardware HKDF Expand");
    
//     unsigned char t1_bytes_hw[32];
//     if (hardware_result == 0) {
//         printf("Hardware result: SUCCESS\n");
        
//         /* Convert result back to bytes */
//         for (int i = 0; i < 8; i++) {
//             uint32_t lower_32 = (uint32_t)(mac_hkdf[i] & 0xFFFFFFFF);
//             t1_bytes_hw[i*4+0] = (lower_32 >> 24) & 0xFF;
//             t1_bytes_hw[i*4+1] = (lower_32 >> 16) & 0xFF;
//             t1_bytes_hw[i*4+2] = (lower_32 >> 8) & 0xFF;
//             t1_bytes_hw[i*4+3] = (lower_32 >> 0) & 0xFF;
//         }
        
//         printf("Hardware T(1) output:\n");
//         printf("  ");
//         for (int i = 0; i < 32; i++) {
//             printf("%02x", t1_bytes_hw[i]);
//         }
//         printf("\n");
//     } else {
//         printf("Hardware result: FAILED (%d)\n", hardware_result);
//     }

    
//     /* ========================================= */
//     /* WOLFSSL SOFTWARE HKDF EXPAND TEST        */
//     /* ========================================= */
//     printf("\n--- WolfSSL Software HKDF Expand ---\n");
    
//     unsigned char okm_wolfssl[32];  /* Output Key Material from WolfSSL */
    
//     start_timing();
//     int wolfssl_result = wc_HKDF_Expand(WC_SHA256,           /* Hash algorithm */
//                                        prk_key, 32,          /* PRK key */
//                                        info_context, 64,     /* Info (KEM context only) */
//                                        okm_wolfssl, 32);     /* Output buffer */
//     end_timing("WolfSSL HKDF Expand");
    
//     printf("WolfSSL result: %s\n", wolfssl_result == 0 ? "SUCCESS" : "FAILED");
//     if (wolfssl_result == 0) {
//         printf("WolfSSL T(1) output:\n");
//         printf("  ");
//         for (int i = 0; i < 32; i++) {
//             printf("%02x", okm_wolfssl[i]);
//         }
//         printf("\n");
//     } else {
//         printf("WolfSSL HKDF Expand failed with error: %d\n", wolfssl_result);
//     }
    
    
//     /* ========================================= */
//     /* COMPARISON AND VERIFICATION              */
//     /* ========================================= */
//     printf("\n--- Comparison Results ---\n");
    
//     if (wolfssl_result == 0 && hardware_result == 0) {
//         /* Both succeeded - compare outputs */
//         int outputs_match = (memcmp(okm_wolfssl, t1_bytes_hw, 32) == 0);
        
//         printf("Both implementations completed successfully\n");
//         printf("Output comparison: %s\n", outputs_match ? "MATCH ✅" : "MISMATCH ❌");
        
//         if (!outputs_match) {
//             printf("\nDetailed comparison:\n");
//             printf("WolfSSL : ");
//             for (int i = 0; i < 32; i++) printf("%02x", okm_wolfssl[i]);
//             printf("\nHardware: ");
//             for (int i = 0; i < 32; i++) printf("%02x", t1_bytes_hw[i]);
//             printf("\n");
            
//             /* Find first mismatch */
//             for (int i = 0; i < 32; i++) {
//                 if (okm_wolfssl[i] != t1_bytes_hw[i]) {
//                     printf("First mismatch at byte %d: WolfSSL=0x%02x, Hardware=0x%02x\n", 
//                            i, okm_wolfssl[i], t1_bytes_hw[i]);
//                     break;
//                 }
//             }
//         }
        
//     } else if (wolfssl_result == 0 && hardware_result != 0) {
//         printf("WolfSSL succeeded, Hardware failed\n");
//         printf("❌ Hardware implementation needs fixing\n");
        
//     } else if (wolfssl_result != 0 && hardware_result == 0) {
//         printf("Hardware succeeded, WolfSSL failed (unexpected)\n");
//         printf("⚠️ WolfSSL error may indicate test setup issue\n");
        
//     } else {
//         printf("Both implementations failed\n");
//         printf("❌ Test setup or input data may be incorrect\n");
//     }
    
//     /* ========================================= */
//     /* FINAL ASSESSMENT                         */
//     /* ========================================= */
//     printf("\n--- Final Assessment ---\n");
    
//     if (wolfssl_result == 0 && hardware_result == 0) {
//         int match = (memcmp(okm_wolfssl, t1_bytes_hw, 32) == 0);
//         if (match) {
//             printf("🎉 SUCCESS: Hardware HKDF Expand matches WolfSSL perfectly!\n");
//             printf("✅ Your 65-byte message handling is working correctly\n");
//             printf("✅ Hardware chunking implementation is correct\n");
//             printf("✅ Vietnamese pattern conversion is working\n");
//             printf("✅ Ready for HPKE integration!\n");
//         } else {
//             printf("⚠️ PARTIAL SUCCESS: Both work but outputs differ\n");
//             printf("🔍 Check: Vietnamese pattern packing\n");
//             printf("🔍 Check: Message structure (info vs info+counter)\n");
//             printf("🔍 Check: Endianness handling\n");
//         }
//     } else {
//         printf("❌ TEST FAILED: Implementation issues detected\n");
//         printf("🔧 Debug hardware implementation\n");
//         printf("🔧 Check 65-byte message handling\n");
//         printf("🔧 Verify chunking logic\n");
//     }
    
//     printf("\n=== HKDF Expand 65-byte Test Complete ===\n");
// }


// /* Side-by-side HKDF Extract test: WolfSSL vs Hardware */
// static int test_hkdf_extract_side_by_side(void)
// {
//     // printf("\n======================================================\n");
//     // printf("=== HKDF Extract Side-by-Side Comparison Test ===\n");
//     // printf("======================================================\n");
    
//     int overall_result = 0;
    
//     /* Test Case 1: RFC 5869 Test Vector 1 */
//     printf("\n--- Test Case 1: RFC 5869 Test Vector 1 ---\n");
    
//     byte ikm1[] = {
//         0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
//         0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
//         0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
//     }; /* 22 bytes */
    
//     byte salt1[] = {
//         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//         0x08, 0x09, 0x0a, 0x0b, 0x0c
//     }; /* 13 bytes */
    
//     byte prk1_hw[32];
//     byte prk1_sw[32];
    
//     /* Expected PRK from RFC 5869 */
//     byte prk1_expected[] = {
//         0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
//         0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
//         0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
//         0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
//     };
    
//     printf("Input data:\n");
//     print_hex_debug("IKM", ikm1, sizeof(ikm1));
//     print_hex_debug("Salt", salt1, sizeof(salt1));
//     print_hex_debug("Expected PRK", prk1_expected, sizeof(prk1_expected));
    
//     /* Test with WolfSSL software */
//     printf("\n🔧 WolfSSL Software Implementation:\n");
//     start_timing();
//     int ret_sw = wc_HKDF_Extract(WC_SHA256, salt1, sizeof(salt1), ikm1, sizeof(ikm1), prk1_sw);
//     end_timing("WolfSSL HKDF Extract");
    
//     printf("WolfSSL result: %s\n", ret_sw == 0 ? "SUCCESS" : "FAILED");
//     if (ret_sw == 0) {
//         print_hex_debug("WolfSSL PRK", prk1_sw, 32);
//     }
    
//     /* Test with hardware */
//     printf("\n⚡ Hardware Implementation (hmacsha_compute):\n");
//     start_timing();
//     int ret_hw = hw_HKDF_Extract_with_hmacsha(salt1, sizeof(salt1), ikm1, sizeof(ikm1), prk1_hw);
//     end_timing("Hardware HKDF Extract");
    
//     printf("Hardware result: %s\n", ret_hw == 0 ? "SUCCESS" : "FAILED");
//     if (ret_hw == 0) {
//         print_hex_debug("Hardware PRK", prk1_hw, 32);
//     }
    
//     /* Verify results */
//     printf("\n📊 Verification Results:\n");
//     int hw_vs_expected = (ret_hw == 0) && (memcmp(prk1_hw, prk1_expected, 32) == 0);
//     int sw_vs_expected = (ret_sw == 0) && (memcmp(prk1_sw, prk1_expected, 32) == 0);
//     int hw_vs_sw = (ret_hw == 0) && (ret_sw == 0) && (memcmp(prk1_hw, prk1_sw, 32) == 0);
    
//     printf("Hardware vs Expected: %s\n", hw_vs_expected ? "MATCH ✅" : "MISMATCH ❌");
//     printf("Software vs Expected: %s\n", sw_vs_expected ? "MATCH ✅" : "MISMATCH ❌");
//     printf("Hardware vs Software: %s\n", hw_vs_sw ? "MATCH ✅" : "MISMATCH ❌");
    
//     if (!hw_vs_sw || !hw_vs_expected || !sw_vs_expected) {
//         overall_result = -1;
//     }
    
//     /* Test Case 2: No salt (HPKE style) */
//     printf("\n--- Test Case 2: No Salt (HPKE Style) ---\n");
    
//     byte ikm2[] = {
//         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
//         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
//         0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
//         0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
//     }; /* 32 bytes - typical DH output */
    
//     byte prk2_hw[32];
//     byte prk2_sw[32];
    
//     printf("Testing with 32-byte IKM, no salt (HPKE pattern):\n");
//     print_hex_debug("IKM (32 bytes)", ikm2, sizeof(ikm2));
    
//     /* Test with WolfSSL software */
//     printf("\n🔧 WolfSSL Software Implementation:\n");
//     start_timing();
//     int ret2_sw = wc_HKDF_Extract(WC_SHA256, NULL, 0, ikm2, sizeof(ikm2), prk2_sw);
//     end_timing("WolfSSL HKDF Extract (no salt)");
    
//     printf("WolfSSL result: %s\n", ret2_sw == 0 ? "SUCCESS" : "FAILED");
//     if (ret2_sw == 0) {
//         print_hex_debug("WolfSSL PRK", prk2_sw, 32);
//     }
    
//     /* Test with hardware */
//     printf("\n⚡ Hardware Implementation (hmacsha_compute):\n");
//     start_timing();
//     int ret2_hw = hw_HKDF_Extract_with_hmacsha(NULL, 0, ikm2, sizeof(ikm2), prk2_hw);
//     end_timing("Hardware HKDF Extract (no salt)");
    
//     printf("Hardware result: %s\n", ret2_hw == 0 ? "SUCCESS" : "FAILED");
//     if (ret2_hw == 0) {
//         print_hex_debug("Hardware PRK", prk2_hw, 32);
//     }
    
//     /* Verify results */
//     printf("\n📊 Verification Results:\n");
//     int match2 = (ret2_hw == 0) && (ret2_sw == 0) && (memcmp(prk2_hw, prk2_sw, 32) == 0);
//     printf("Hardware vs Software: %s\n", match2 ? "MATCH ✅" : "MISMATCH ❌");
    
//     if (!match2) {
//         overall_result = -1;
//     }
    
//     /* Test Case 3: Small salt and IKM */
//     printf("\n--- Test Case 3: Small Salt and IKM ---\n");
    
//     byte ikm3[] = {0x42, 0x43, 0x44, 0x45}; /* 4 bytes */
//     byte salt3[] = {0xa1, 0xa2}; /* 2 bytes */
    
//     byte prk3_hw[32];
//     byte prk3_sw[32];
    
//     printf("Testing with small data sizes:\n");
//     print_hex_debug("IKM (4 bytes)", ikm3, sizeof(ikm3));
//     print_hex_debug("Salt (2 bytes)", salt3, sizeof(salt3));
    
//     /* Test with WolfSSL software */
//     printf("\n🔧 WolfSSL Software Implementation:\n");
//     int ret3_sw = wc_HKDF_Extract(WC_SHA256, salt3, sizeof(salt3), ikm3, sizeof(ikm3), prk3_sw);
//     printf("WolfSSL result: %s\n", ret3_sw == 0 ? "SUCCESS" : "FAILED");
//     if (ret3_sw == 0) {
//         print_hex_debug("WolfSSL PRK", prk3_sw, 32);
//     }
    
//     /* Test with hardware */
//     printf("\n⚡ Hardware Implementation (hmacsha_compute):\n");
//     int ret3_hw = hw_HKDF_Extract_with_hmacsha(salt3, sizeof(salt3), ikm3, sizeof(ikm3), prk3_hw);
//     printf("Hardware result: %s\n", ret3_hw == 0 ? "SUCCESS" : "FAILED");
//     if (ret3_hw == 0) {
//         print_hex_debug("Hardware PRK", prk3_hw, 32);
//     }
    
//     /* Verify results */
//     printf("\n📊 Verification Results:\n");
//     int match3 = (ret3_hw == 0) && (ret3_sw == 0) && (memcmp(prk3_hw, prk3_sw, 32) == 0);
//     printf("Hardware vs Software: %s\n", match3 ? "MATCH ✅" : "MISMATCH ❌");
    
//     if (!match3) {
//         overall_result = -1;
//     }
    
//     /* Final Summary */
//     printf("\n======================================================\n");
//     printf("=== FINAL TEST SUMMARY ===\n");
//     printf("======================================================\n");
//     printf("Test 1 (RFC 5869 with salt): %s\n", 
//            (hw_vs_sw && hw_vs_expected && sw_vs_expected) ? "PASS ✅" : "FAIL ❌");
//     printf("Test 2 (HPKE no salt):       %s\n", match2 ? "PASS ✅" : "FAIL ❌");
//     printf("Test 3 (Small data):         %s\n", match3 ? "PASS ✅" : "FAIL ❌");
    
//     if (overall_result == 0) {
//         printf("\n🎉 ALL TESTS PASSED!\n");
//         printf("✅ Hardware HMAC-SHA matches WolfSSL HKDF Extract perfectly\n");
//         printf("✅ Your hmacsha_compute function is working correctly\n");
//         printf("✅ Ready for HPKE integration\n");
//     } else {
//         printf("\n⚠️ SOME TESTS FAILED\n");
//         printf("❌ Hardware implementation needs debugging\n");
//         printf("🔍 Check data packing, endianness, or hardware setup\n");
//     }
    
//     return overall_result;
// }

// /* Side-by-side HKDF Expand test: WolfSSL vs Hardware */
// static int test_hkdf_expand_side_by_side(void)
// {
//     printf("\n======================================================\n");
//     printf("=== HKDF Expand Side-by-Side Comparison Test ===\n");
//     printf("======================================================\n");
    
//     int overall_result = 0;
    
//     /* Test Case 1: RFC 5869 Test Vector 1 - Expand */
//     printf("\n--- Test Case 1: RFC 5869 Test Vector 1 (Expand) ---\n");
    
//     /* PRK from previous extract operation */
//     byte prk1[] = {
//         0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
//         0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
//         0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
//         0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
//     };
    
//     byte info1[] = {
//         0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
//         0xf8, 0xf9
//     }; /* 10 bytes */
    
//     word32 okm_len = 42;  /* RFC 5869 test vector */
//     byte okm1_hw[42];
//     byte okm1_sw[42];
    
//     /* Expected OKM from RFC 5869 */
//     byte okm1_expected[] = {
//         0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
//         0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
//         0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
//         0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
//         0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
//         0x58, 0x65
//     };
    
//     printf("Input data:\n");
//     print_hex_debug("PRK", prk1, sizeof(prk1));
//     print_hex_debug("Info", info1, sizeof(info1));
//     printf("OKM length: %u bytes\n", okm_len);
//     print_hex_debug("Expected OKM", okm1_expected, sizeof(okm1_expected));
    
//     /* Test with WolfSSL software */
//     printf("\n🔧 WolfSSL Software Implementation:\n");
//     start_timing();
//     int ret_sw = wc_HKDF_Expand(WC_SHA256, prk1, sizeof(prk1), info1, sizeof(info1), okm1_sw, okm_len);
//     end_timing("WolfSSL HKDF Expand");
    
//     printf("WolfSSL result: %s\n", ret_sw == 0 ? "SUCCESS" : "FAILED");
//     if (ret_sw == 0) {
//         print_hex_debug("WolfSSL OKM", okm1_sw, okm_len);
//     }
    
//     /* Test with hardware */
//     printf("\n⚡ Hardware Implementation (hmacsha_compute):\n");
//     start_timing();
//     int ret_hw = hw_HKDF_Expand(prk1, sizeof(prk1), info1, sizeof(info1), okm1_hw, okm_len);
//     end_timing("Hardware HKDF Expand");
    
//     printf("Hardware result: %s\n", ret_hw == 0 ? "SUCCESS" : "FAILED");
//     if (ret_hw == 0) {
//         print_hex_debug("Hardware OKM", okm1_hw, okm_len);
//     }
    
//     /* Verify results */
//     printf("\n📊 Verification Results:\n");
//     int hw_vs_expected = (ret_hw == 0) && (memcmp(okm1_hw, okm1_expected, okm_len) == 0);
//     int sw_vs_expected = (ret_sw == 0) && (memcmp(okm1_sw, okm1_expected, okm_len) == 0);
//     int hw_vs_sw = (ret_hw == 0) && (ret_sw == 0) && (memcmp(okm1_hw, okm1_sw, okm_len) == 0);
    
//     printf("Hardware vs Expected: %s\n", hw_vs_expected ? "MATCH ✅" : "MISMATCH ❌");
//     printf("Software vs Expected: %s\n", sw_vs_expected ? "MATCH ✅" : "MISMATCH ❌");
//     printf("Hardware vs Software: %s\n", hw_vs_sw ? "MATCH ✅" : "MISMATCH ❌");
    
//     if (!hw_vs_sw || !hw_vs_expected || !sw_vs_expected) {
//         overall_result = -1;
//     }
    
//     /* Test Case 2: HPKE Style - Key Derivation */
//     printf("\n--- Test Case 2: HPKE Key Derivation ---\n");
    
//     /* Example PRK from HPKE */
//     byte prk2[] = {
//         0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
//         0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
//         0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
//         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
//     };
    
//     /* HPKE key info: "key" + 16-bit length in network byte order */
//     byte info2[] = {0x00, 0x01, 0x00, 0x10};  /* "key" + length 16 */
//     word32 okm2_len = 16;  /* AES-128 key size */
    
//     byte okm2_hw[16];
//     byte okm2_sw[16];
    
//     printf("Testing HPKE key derivation pattern:\n");
//     print_hex_debug("PRK (32 bytes)", prk2, sizeof(prk2));
//     print_hex_debug("Info (key derivation)", info2, sizeof(info2));
//     printf("OKM length: %u bytes (AES-128 key)\n", okm2_len);
    
//     /* Test with WolfSSL software */
//     printf("\n🔧 WolfSSL Software Implementation:\n");
//     start_timing();
//     int ret2_sw = wc_HKDF_Expand(WC_SHA256, prk2, sizeof(prk2), info2, sizeof(info2), okm2_sw, okm2_len);
//     end_timing("WolfSSL HKDF Expand (key derivation)");
    
//     printf("WolfSSL result: %s\n", ret2_sw == 0 ? "SUCCESS" : "FAILED");
//     if (ret2_sw == 0) {
//         print_hex_debug("WolfSSL derived key", okm2_sw, okm2_len);
//     }
    
//     /* Test with hardware */
//     printf("\n⚡ Hardware Implementation (hmacsha_compute):\n");
//     start_timing();
//     int ret2_hw = hw_HKDF_Expand(prk2, sizeof(prk2), info2, sizeof(info2), okm2_hw, okm2_len);
//     end_timing("Hardware HKDF Expand (key derivation)");
    
//     printf("Hardware result: %s\n", ret2_hw == 0 ? "SUCCESS" : "FAILED");
//     if (ret2_hw == 0) {
//         print_hex_debug("Hardware derived key", okm2_hw, okm2_len);
//     }
    
//     /* Verify results */
//     printf("\n📊 Verification Results:\n");
//     int match2 = (ret2_hw == 0) && (ret2_sw == 0) && (memcmp(okm2_hw, okm2_sw, okm2_len) == 0);
//     printf("Hardware vs Software: %s\n", match2 ? "MATCH ✅" : "MISMATCH ❌");
    
//     if (!match2) {
//         overall_result = -1;
//     }
    
//     /* Test Case 3: HPKE Nonce Derivation */
//     printf("\n--- Test Case 3: HPKE Nonce Derivation ---\n");
    
//     /* HPKE nonce info: "base_nonce" + 12-bit length */
//     byte info3[] = {0x00, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x00};  /* "base_nonce" + length 12 */
//     word32 okm3_len = 12;  /* GCM nonce size */
    
//     byte okm3_hw[12];
//     byte okm3_sw[12];
    
//     printf("Testing HPKE nonce derivation pattern:\n");
//     print_hex_debug("PRK (32 bytes)", prk2, sizeof(prk2));
//     print_hex_debug("Info (nonce derivation)", info3, sizeof(info3));
//     printf("OKM length: %u bytes (GCM nonce)\n", okm3_len);
    
//     /* Test with WolfSSL software */
//     printf("\n🔧 WolfSSL Software Implementation:\n");
//     int ret3_sw = wc_HKDF_Expand(WC_SHA256, prk2, sizeof(prk2), info3, sizeof(info3), okm3_sw, okm3_len);
//     printf("WolfSSL result: %s\n", ret3_sw == 0 ? "SUCCESS" : "FAILED");
//     if (ret3_sw == 0) {
//         print_hex_debug("WolfSSL derived nonce", okm3_sw, okm3_len);
//     }
    
//     /* Test with hardware */
//     printf("\n⚡ Hardware Implementation (hmacsha_compute):\n");
//     int ret3_hw = hw_HKDF_Expand(prk2, sizeof(prk2), info3, sizeof(info3), okm3_hw, okm3_len);
//     printf("Hardware result: %s\n", ret3_hw == 0 ? "SUCCESS" : "FAILED");
//     if (ret3_hw == 0) {
//         print_hex_debug("Hardware derived nonce", okm3_hw, okm3_len);
//     }
    
//     /* Verify results */
//     printf("\n📊 Verification Results:\n");
//     int match3 = (ret3_hw == 0) && (ret3_sw == 0) && (memcmp(okm3_hw, okm3_sw, okm3_len) == 0);
//     printf("Hardware vs Software: %s\n", match3 ? "MATCH ✅" : "MISMATCH ❌");
    
//     if (!match3) {
//         overall_result = -1;
//     }
    
//     /* Final Summary */
//     printf("\n======================================================\n");
//     printf("=== HKDF EXPAND TEST SUMMARY ===\n");
//     printf("======================================================\n");
//     printf("Test 1 (RFC 5869 expand):   %s\n", 
//            (hw_vs_sw && hw_vs_expected && sw_vs_expected) ? "PASS ✅" : "FAIL ❌");
//     printf("Test 2 (HPKE key derive):   %s\n", match2 ? "PASS ✅" : "FAIL ❌");
//     printf("Test 3 (HPKE nonce derive): %s\n", match3 ? "PASS ✅" : "FAIL ❌");
    
//     if (overall_result == 0) {
//         printf("\n🎉 ALL HKDF EXPAND TESTS PASSED!\n");
//         printf("✅ Hardware HMAC-SHA matches WolfSSL HKDF Expand perfectly\n");
//         printf("✅ Your hmacsha_compute function handles multi-iteration HKDF correctly\n");
//         printf("✅ Ready for full HPKE integration with hardware HKDF\n");
//     } else {
//         printf("\n⚠️ SOME HKDF EXPAND TESTS FAILED\n");
//         printf("❌ Hardware implementation needs debugging\n");
//         printf("🔍 Check iteration logic, message concatenation, or T(i-1) chaining\n");
//     }
    
//     return overall_result;
// }


/* Side-by-side compare: firmware vs wolfSSL on Testcase 2 (AES-128, AAD+PT) */
// static int test_gcm_compare_tc2(void* aes_gcmctrl)
// {
//     /* Testcase 2 vectors */
// // * Use EXACT values from your HPKE seal operation */
//     static const byte key[16] = {
//         0xff,0xa6,0x40,0xee,0x8e,0xd4,0x94,0x37,0x9e,0xfa,0xa5,0x39,0x59,0xa8,0x41,0x88
//     };
//     static const byte iv[12] = {
//         0xdb,0x0f,0xce,0x8e,0xd3,0xfa,0xb6,0xd6,0x93,0xe5,0x1f,0x95
//     };
//     static const byte aad[8] = {
//         0x74,0x65,0x73,0x74,0x20,0x61,0x61,0x64  /* "test aad" */
//     };
//     static const byte pt[11] = {
//         0x48,0x65,0x6c,0x6c,0x6f,0x20,0x48,0x50,0x4b,0x45,0x21  /* "Hello HPKE!" */
//     };
    
//     /* Expected results from your HPKE operation */
//     static const byte expected_ct[11] = {
//         0x15,0xe3,0x85,0x68,0x12,0x06,0xc4,0x2c,0xc1,0x2e,0xf0
//     };
//     static const byte expected_tag[16] = {
//         0x9f,0x0b,0x42,0x33,0xf0,0xf1,0x4c,0xcd,0xe1,0xff,0x9e,0x57,0xaa,0x09,0x05,0xe4
//     };
    
//     enum { TAG_SZ = 16 };

//     /* Hardware format buffers */
//     const word32 pt_qw  = 6;  /* 48 bytes = 6 qwords */
//     const word32 aad_qw = 4;  /* 28 bytes padded to 4 qwords */
//     const word32 key_qw = 4;  /* Always 4 qwords (AES-256 format, zero-padded for AES-128) */
//     const word32 iv_qw  = 2;  /* 12 bytes padded to 2 qwords */
//     const word32 tag_qw = 2;  /* 16 bytes = 2 qwords */

//     uint64_t hw_key[4] = {0};
//     uint64_t hw_iv[2]  = {0};
//     uint64_t hw_aad[4] = {0};
//     uint64_t hw_pt[6]  = {0};
//     uint64_t hw_ct[6]  = {0};
//     uint64_t hw_tag[2] = {0};
//     uint64_t hw_recovered_pt[6] = {0};

//     /* Working buffers for comparison */
//     byte hw_ct_bytes[sizeof(pt)] = {0};
//     byte hw_tag_bytes[TAG_SZ] = {0};
//     byte hw_recovered_bytes[sizeof(pt)] = {0};

//     /* Pack inputs to hardware format */
//     pack_bytes_to_qwords_be_fixed(key, sizeof(key), hw_key, key_qw);
//     pack_bytes_to_qwords_be_fixed(iv,  sizeof(iv),  hw_iv,  iv_qw);
//     pack_bytes_to_qwords_be_fixed(aad, sizeof(aad), hw_aad, aad_qw);
//     pack_bytes_to_qwords_be_fixed(pt,  sizeof(pt),  hw_pt,  pt_qw);

//     /* === STEP 1: HARDWARE ENCRYPTION === */
//     // printf("\n--- Hardware AES-GCM Encryption ---\n");
//     // printf("Encrypting %u bytes plaintext with %u bytes AAD\n", (unsigned)sizeof(pt), (unsigned)sizeof(aad));
    
//     // start_timing();
//     hw_aes_gcm_reset(aes_gcmctrl);
//     hw_aes_gcm_encrypt(aes_gcmctrl,
//                        hw_ct, hw_pt, sizeof(pt),
//                        hw_key, sizeof(key), hw_iv, sizeof(iv),
//                        hw_aad, sizeof(aad), hw_tag, TAG_SZ);
//     // end_timing("Hardware AES-GCM Encryption");

//     /* Convert encryption results to bytes */
//     unpack_qwords_to_bytes_be(hw_ct,  sizeof(pt), hw_ct_bytes);
//     unpack_qwords_to_bytes_be(hw_tag, TAG_SZ,     hw_tag_bytes);

//     print_hex_debug("Ciphertext", hw_ct_bytes, sizeof(pt));
//     hw_ct[1] = hw_ct[1] & 0xFFFFFF0000000000ULL; 

//     // start_timing();
//     hw_aes_gcm_reset(aes_gcmctrl);
//     int decrypt_ret = hw_aes_gcm_decrypt_verify(aes_gcmctrl, 
//                                                 hw_recovered_pt, hw_ct, sizeof(pt),
//                                                 hw_key, sizeof(key), hw_iv, sizeof(iv),
//                                                 hw_aad, sizeof(aad), hw_tag, TAG_SZ);
//     // end_timing("Hardware AES-GCM Decryption");

//     if (decrypt_ret != 0) {
//         printf("Hardware decryption/verification FAILED with error: %d\n", decrypt_ret);
//         if (decrypt_ret == -6) {
//             printf("Authentication tag verification failed\n");
//         }
//         return decrypt_ret;
//     }

//     /* Convert decryption results to bytes */
//     unpack_qwords_to_bytes_be(hw_recovered_pt, sizeof(pt), hw_recovered_bytes);

//     // printf("Decryption results:\n");
//     // print_hex_debug("Recovered Plaintext", hw_recovered_bytes, sizeof(pt));

//     /* === STEP 3: ROUND-TRIP VERIFICATION === */
//     // printf("\n--- Round-trip Verification ---\n");
//     int pt_match = (XMEMCMP(pt, hw_recovered_bytes, sizeof(pt)) == 0);
    
//     // printf("Plaintext recovery validation:\n");
//     // printf("  Original plaintext matches recovered: %s\n", pt_match ? "PASS" : "FAIL");

//     if (!pt_match) {
//         printf("Round-trip validation FAILED\n");
//         print_hex_debug("Original plaintext", pt, sizeof(pt));
//         print_hex_debug("Recovered plaintext", hw_recovered_bytes, sizeof(pt));
        
//         /* Find first mismatch */
//         for (unsigned i = 0; i < sizeof(pt); i++) {
//             if (pt[i] != hw_recovered_bytes[i]) {
//                 printf("First mismatch at byte %u: orig=0x%02x recovered=0x%02x\n", 
//                        i, pt[i], hw_recovered_bytes[i]);
//                 break;
//             }
//         }
//         return -1;
//     }

//     printf("OK\n");
//     return 0;
// }



// /* Side-by-side HKDF Expand test: WolfSSL vs Hardware */
// static int test_hkdf_expand_side_by_side(void)
// {
//     // printf("\n======================================================\n");
//     // printf("=== HKDF Expand Side-by-Side Comparison Test ===\n");
//     // printf("======================================================\n");
    
//     int overall_result = 0;
    
//     /* Test Case 1: RFC 5869 Test Vector 1 - Expand */
//     printf("\n--- Test Case 1: RFC 5869 Test Vector 1 (Expand) ---\n");
    
//     /* PRK from previous extract operation */
//     byte prk1[] = {
//         0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
//         0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
//         0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
//         0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
//     };
    
//     byte info1[] = {
//         0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
//         0xf8, 0xf9
//     }; /* 10 bytes */
    
//     word32 okm_len = 42;  /* RFC 5869 test vector */
//     byte okm1_hw[42];
//     byte okm1_sw[42];
    
//     /* Expected OKM from RFC 5869 */
//     byte okm1_expected[] = {
//         0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
//         0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
//         0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
//         0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
//         0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
//         0x58, 0x65
//     };
    
//     // printf("Input data:\n");
//     // print_hex_debug("PRK", prk1, sizeof(prk1));
//     // print_hex_debug("Info", info1, sizeof(info1));
//     // printf("OKM length: %u bytes\n", okm_len);
//     // print_hex_debug("Expected OKM", okm1_expected, sizeof(okm1_expected));
    

//     /* Test with hardware */
//     printf("\n⚡ Hardware Implementation (hmacsha_compute):\n");
//     start_timing();
//     int ret_hw = hw_HKDF_Expand(prk1, sizeof(prk1), info1, sizeof(info1), okm1_hw, okm_len);
//     end_timing("Hardware HKDF Expand");
    
//     printf("Hardware result: %s\n", ret_hw == 0 ? "SUCCESS" : "FAILED");
//     if (ret_hw == 0) {
//         print_hex_debug("Hardware OKM", okm1_hw, okm_len);
//     }
    

//     // /* Test with WolfSSL software */
//     // printf("\n🔧 WolfSSL Software Implementation:\n");
//     // start_timing();
//     // int ret_sw = wc_HKDF_Expand(WC_SHA256, prk1, sizeof(prk1), info1, sizeof(info1), okm1_sw, okm_len);
//     // end_timing("WolfSSL HKDF Expand");
    
//     // printf("WolfSSL result: %s\n", ret_sw == 0 ? "SUCCESS" : "FAILED");
//     // if (ret_sw == 0) {
//     //     print_hex_debug("WolfSSL OKM", okm1_sw, okm_len);
//     // }
    
//     // /* Verify results */
//     // printf("\n📊 Verification Results:\n");
//     // int hw_vs_expected = (ret_hw == 0) && (memcmp(okm1_hw, okm1_expected, okm_len) == 0);
//     // int sw_vs_expected = (ret_sw == 0) && (memcmp(okm1_sw, okm1_expected, okm_len) == 0);
//     // int hw_vs_sw = (ret_hw == 0) && (ret_sw == 0) && (memcmp(okm1_hw, okm1_sw, okm_len) == 0);
    
//     // printf("Hardware vs Expected: %s\n", hw_vs_expected ? "MATCH ✅" : "MISMATCH ❌");
//     // printf("Software vs Expected: %s\n", sw_vs_expected ? "MATCH ✅" : "MISMATCH ❌");
//     // printf("Hardware vs Software: %s\n", hw_vs_sw ? "MATCH ✅" : "MISMATCH ❌");
    
//     // if (!hw_vs_sw || !hw_vs_expected || !sw_vs_expected) {
//     //     overall_result = -1;
//     // }
    
//     /* Test Case 2: HPKE Style - Key Derivation */
//     printf("\n--- Test Case 2: HPKE Key Derivation ---\n");
    
//     /* Example PRK from HPKE */
//     byte prk2[] = {
//         0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
//         0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
//         0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
//         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
//     };
    
//     /* HPKE key info: "key" + 16-bit length in network byte order */
//     byte info2[] = {0x00, 0x01, 0x00, 0x10};  /* "key" + length 16 */
//     word32 okm2_len = 16;  /* AES-128 key size */
    
//     byte okm2_hw[16];
//     byte okm2_sw[16];
    
//     // printf("Testing HPKE key derivation pattern:\n");
//     // print_hex_debug("PRK (32 bytes)", prk2, sizeof(prk2));
//     // print_hex_debug("Info (key derivation)", info2, sizeof(info2));
//     // printf("OKM length: %u bytes (AES-128 key)\n", okm2_len);
    
//     // /* Test with WolfSSL software */
//     // printf("\n🔧 WolfSSL Software Implementation:\n");
//     // start_timing();
//     // int ret2_sw = wc_HKDF_Expand(WC_SHA256, prk2, sizeof(prk2), info2, sizeof(info2), okm2_sw, okm2_len);
//     // end_timing("WolfSSL HKDF Expand (key derivation)");
    
//     // printf("WolfSSL result: %s\n", ret2_sw == 0 ? "SUCCESS" : "FAILED");
//     // if (ret2_sw == 0) {
//     //     print_hex_debug("WolfSSL derived key", okm2_sw, okm2_len);
//     // }
    
//     /* Test with hardware */
//     printf("\n⚡ Hardware Implementation (hmacsha_compute):\n");
//     start_timing();
//     int ret2_hw = hw_HKDF_Expand(prk2, sizeof(prk2), info2, sizeof(info2), okm2_hw, okm2_len);
//     end_timing("Hardware HKDF Expand (key derivation)");
    
//     printf("Hardware result: %s\n", ret2_hw == 0 ? "SUCCESS" : "FAILED");
//     if (ret2_hw == 0) {
//         print_hex_debug("Hardware derived key", okm2_hw, okm2_len);
//     }
    
//     // /* Verify results */
//     // printf("\n📊 Verification Results:\n");
//     // int match2 = (ret2_hw == 0) && (ret2_sw == 0) && (memcmp(okm2_hw, okm2_sw, okm2_len) == 0);
//     // printf("Hardware vs Software: %s\n", match2 ? "MATCH ✅" : "MISMATCH ❌");
    
//     // if (!match2) {
//     //     overall_result = -1;
//     // }
    
//     /* Test Case 3: HPKE Nonce Derivation */
//     printf("\n--- Test Case 3: HPKE Nonce Derivation ---\n");
    
//     /* HPKE nonce info: "base_nonce" + 12-bit length */
//     byte info3[] = {0x00, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x00};  /* "base_nonce" + length 12 */
//     word32 okm3_len = 12;  /* GCM nonce size */
    
//     byte okm3_hw[12];
//     byte okm3_sw[12];
    
//     printf("Testing HPKE nonce derivation pattern:\n");
//     print_hex_debug("PRK (32 bytes)", prk2, sizeof(prk2));
//     print_hex_debug("Info (nonce derivation)", info3, sizeof(info3));
//     printf("OKM length: %u bytes (GCM nonce)\n", okm3_len);
    
//     /* Test with WolfSSL software */
//     printf("\n🔧 WolfSSL Software Implementation:\n");
//     int ret3_sw = wc_HKDF_Expand(WC_SHA256, prk2, sizeof(prk2), info3, sizeof(info3), okm3_sw, okm3_len);
//     printf("WolfSSL result: %s\n", ret3_sw == 0 ? "SUCCESS" : "FAILED");
//     if (ret3_sw == 0) {
//         print_hex_debug("WolfSSL derived nonce", okm3_sw, okm3_len);
//     }
    
//     /* Test with hardware */
//     printf("\n⚡ Hardware Implementation (hmacsha_compute):\n");
//     int ret3_hw = hw_HKDF_Expand(prk2, sizeof(prk2), info3, sizeof(info3), okm3_hw, okm3_len);
//     printf("Hardware result: %s\n", ret3_hw == 0 ? "SUCCESS" : "FAILED");
//     if (ret3_hw == 0) {
//         print_hex_debug("Hardware derived nonce", okm3_hw, okm3_len);
//     }
    
//     /* Verify results */
//     printf("\n📊 Verification Results:\n");
//     int match3 = (ret3_hw == 0) && (ret3_sw == 0) && (memcmp(okm3_hw, okm3_sw, okm3_len) == 0);
//     printf("Hardware vs Software: %s\n", match3 ? "MATCH ✅" : "MISMATCH ❌");
    
//     if (!match3) {
//         overall_result = -1;
//     }
    
//     /* Test Case 4: HPKE-Style Large Context (65+ bytes) - THE NEW TEST */
//     printf("\n--- Test Case 4: HPKE Large Context (65+ bytes) ---\n");
    
//     /* Same PRK as Test Case 2 */
//     byte prk4[] = {
//         0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
//         0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
//         0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
//         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
//     };
    
//     /* Large info context: Simulating HPKE KEM context (64 bytes) + additional data */
//     byte info4[72];  /* 72 bytes > 64-byte limit */
    
//     /* Build large info context */
//     /* First 32 bytes: Simulated ephemeral public key */
//     for (int i = 0; i < 32; i++) {
//         info4[i] = 0x11 + (i % 16);  /* Pattern: 0x11-0x20 repeated */
//     }
    
//     /* Next 32 bytes: Simulated receiver public key */
//     for (int i = 0; i < 32; i++) {
//         info4[32 + i] = 0x33 + (i % 16);  /* Pattern: 0x33-0x42 repeated */
//     }
    
//     /* Additional 8 bytes: Extra context data */
//     info4[64] = 0x00;  /* Version */
//     info4[65] = 0x01;  /* KEM ID */
//     info4[66] = 0x00;  /* KDF ID */
//     info4[67] = 0x01;  /* AEAD ID */
//     info4[68] = 0xaa;  /* App data */
//     info4[69] = 0xbb;
//     info4[70] = 0xcc;
//     info4[71] = 0xdd;
    
//     word32 okm4_len = 32;  /* 32-byte output */
    
//     byte okm4_hw[32];
//     byte okm4_sw[32];
    
//     printf("Testing large context (72 bytes > 64-byte limit):\n");
//     print_hex_debug("PRK (32 bytes)", prk4, sizeof(prk4));
//     print_hex_debug("Large Info context", info4, sizeof(info4));
//     printf("Info size: %u bytes (exceeds 64-byte limit)\n", (unsigned)sizeof(info4));
//     printf("OKM length: %u bytes\n", okm4_len);
    
//     /* Test with WolfSSL software */
//     printf("\n🔧 WolfSSL Software Implementation:\n");
//     start_timing();
//     int ret4_sw = wc_HKDF_Expand(WC_SHA256, prk4, sizeof(prk4), info4, sizeof(info4), okm4_sw, okm4_len);
//     end_timing("WolfSSL HKDF Expand (72-byte info)");
    
//     printf("WolfSSL result: %s\n", ret4_sw == 0 ? "SUCCESS" : "FAILED");
//     if (ret4_sw == 0) {
//         print_hex_debug("WolfSSL OKM (72-byte info)", okm4_sw, okm4_len);
//     }
    
//     /* Test with hardware */
//     printf("\n⚡ Hardware Implementation (enhanced hmacsha_compute):\n");
//     start_timing();
//     int ret4_hw = hw_HKDF_Expand(prk4, sizeof(prk4), info4, sizeof(info4), okm4_hw, okm4_len);
//     end_timing("Hardware HKDF Expand (72-byte info)");
    
//     printf("Hardware result: %s\n", ret4_hw == 0 ? "SUCCESS" : "FAILED");
//     if (ret4_hw == 0) {
//         print_hex_debug("Hardware OKM (72-byte info)", okm4_hw, okm4_len);
//     }
    
//     /* Verify results */
//     printf("\n📊 Verification Results:\n");
//     int match4 = (ret4_hw == 0) && (ret4_sw == 0) && (memcmp(okm4_hw, okm4_sw, okm4_len) == 0);
//     printf("Hardware vs Software (72-byte info): %s\n", match4 ? "MATCH ✅" : "MISMATCH ❌");
    
//     if (match4) {
//         printf("✅ SUCCESS: Hardware chunking handled 72-byte info correctly!\n");
//         printf("✅ Message breakdown for iteration 1:\n");
//         printf("    T(0):     0 bytes (empty for first iteration)\n");
//         printf("    Info:     72 bytes (large context)\n");
//         printf("    Counter:  1 byte\n");
//         printf("    Total:    73 bytes (requires chunking)\n");
//     } else {
//         printf("❌ Large message chunking failed\n");
//         if (ret4_hw != 0) {
//             printf("   Hardware error: %d\n", ret4_hw);
//         }
//         if (ret4_sw != 0) {
//             printf("   WolfSSL error: %d\n", ret4_sw);
//         }
//         if (ret4_hw == 0 && ret4_sw == 0) {
//             printf("   Output mismatch detected\n");
//             printf("   WolfSSL : ");
//             for (int i = 0; i < 8; i++) printf("%02x", okm4_sw[i]);
//             printf("...\n");
//             printf("   Hardware: ");
//             for (int i = 0; i < 8; i++) printf("%02x", okm4_hw[i]);
//             printf("...\n");
//         }
//         overall_result = -1;
//     }
    
//     /* Test Case 5: Multi-Iteration Large Context (96+ bytes total message) */
//     printf("\n--- Test Case 5: Multi-Iteration Large Context ---\n");
    
//     /* Use even larger info to force multiple iterations */
//     byte info5[80];  /* 80 bytes info */
    
//     /* Build very large info context */
//     for (int i = 0; i < 80; i++) {
//         info5[i] = (byte)(0x50 + (i % 32));  /* Varied pattern */
//     }
    
//     word32 okm5_len = 64;  /* 64-byte output (requires 2 iterations) */
    
//     byte okm5_hw[64];
//     byte okm5_sw[64];
    
//     printf("Testing multi-iteration with large context:\n");
//     print_hex_debug("PRK (32 bytes)", prk4, sizeof(prk4));
//     printf("Large Info size: %u bytes\n", (unsigned)sizeof(info5));
//     printf("OKM length: %u bytes (requires 2 iterations)\n", okm5_len);
//     printf("Expected message sizes:\n");
//     printf("  Iteration 1: T(0)(0) + Info(80) + Counter(1) = 81 bytes\n");
//     printf("  Iteration 2: T(1)(32) + Info(80) + Counter(1) = 113 bytes\n");
    
//     /* Test with WolfSSL software */
//     printf("\n🔧 WolfSSL Software Implementation:\n");
//     start_timing();
//     int ret5_sw = wc_HKDF_Expand(WC_SHA256, prk4, sizeof(prk4), info5, sizeof(info5), okm5_sw, okm5_len);
//     end_timing("WolfSSL HKDF Expand (multi-iteration)");
    
//     printf("WolfSSL result: %s\n", ret5_sw == 0 ? "SUCCESS" : "FAILED");
//     if (ret5_sw == 0) {
//         print_hex_debug("WolfSSL OKM (multi-iteration)", okm5_sw, okm5_len);
//     }
    
//     /* Test with hardware */
//     printf("\n⚡ Hardware Implementation (enhanced hmacsha_compute):\n");
//     start_timing();
//     int ret5_hw = hw_HKDF_Expand(prk4, sizeof(prk4), info5, sizeof(info5), okm5_hw, okm5_len);
//     end_timing("Hardware HKDF Expand (multi-iteration)");
    
//     printf("Hardware result: %s\n", ret5_hw == 0 ? "SUCCESS" : "FAILED");
//     if (ret5_hw == 0) {
//         print_hex_debug("Hardware OKM (multi-iteration)", okm5_hw, okm5_len);
//     }
    
//     /* Verify results */
//     printf("\n📊 Verification Results:\n");
//     int match5 = (ret5_hw == 0) && (ret5_sw == 0) && (memcmp(okm5_hw, okm5_sw, okm5_len) == 0);
//     printf("Hardware vs Software (multi-iteration): %s\n", match5 ? "MATCH ✅" : "MISMATCH ❌");
    
//     if (match5) {
//         printf("✅ SUCCESS: Hardware chunking handled multi-iteration correctly!\n");
//         printf("✅ Both 81-byte and 113-byte messages processed successfully\n");
//     } else {
//         printf("❌ Multi-iteration chunking failed\n");
//         overall_result = -1;
//     }
    
//     if (!match4 || !match5) {
//         overall_result = -1;
//     }
    
//     // /* Final Summary */
//     // printf("\n======================================================\n");
//     // printf("=== HKDF EXPAND TEST SUMMARY ===\n");
//     // printf("======================================================\n");
//     // // printf("Test 1 (RFC 5869 expand):       %s\n", 
//     // //        (hw_vs_sw && hw_vs_expected && sw_vs_expected) ? "PASS ✅" : "FAIL ❌");
//     // printf("Test 2 (HPKE key derive):       %s\n", match2 ? "PASS ✅" : "FAIL ❌");
//     // printf("Test 3 (HPKE nonce derive):     %s\n", match3 ? "PASS ✅" : "FAIL ❌");
//     // printf("Test 4 (Large context 72B):     %s\n", match4 ? "PASS ✅" : "FAIL ❌");
//     // printf("Test 5 (Multi-iteration 113B):  %s\n", match5 ? "PASS ✅" : "FAIL ❌");
    
//     // if (overall_result == 0) {
//     //     printf("\n🎉 ALL HKDF EXPAND TESTS PASSED!\n");
//     //     printf("✅ Hardware HMAC-SHA matches WolfSSL HKDF Expand perfectly\n");
//     //     printf("✅ Your hmacsha_compute function handles multi-iteration HKDF correctly\n");
//     //     printf("✅ Enhanced chunking supports messages > 64 bytes\n");
//     //     printf("✅ Multi-iteration HKDF with large contexts working\n");
//     //     printf("✅ Ready for full HPKE integration with hardware HKDF\n");
//     // } else {
//     //     printf("\n⚠️ SOME HKDF EXPAND TESTS FAILED\n");
//     //     printf("❌ Hardware implementation needs debugging\n");
//     //     printf("🔍 Check iteration logic, message concatenation, or chunking\n");
//     //     printf("🔍 Verify T(i-1) chaining for multi-iteration cases\n");
//     // }
    
//     return overall_result;
// }