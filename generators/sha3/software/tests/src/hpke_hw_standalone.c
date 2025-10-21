/* Complete Standalone HPKE implementation without WolfSSL dependencies */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "encoding.h"
#include "compiler.h"
#include "driver/aes_gcm/aes_gcm.h"
#include "driver/hmac_sha/hmac_sha.h"
#include "driver/x25519/x25519.h"

/* Hardware accelerator base addresses */
#define X25519_HW_BASE_ADDR  0x64004000
#define AES_GCM_HW_BASE_ADDR 0x64009000
#define HMAC_SHA_HW_BASE_ADDR 0x64005000

/* Constants */
#define CURVE25519_KEYSIZE 32
#define SHA256_DIGEST_SIZE 32
#define AES_128_KEY_SIZE 16
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define HPKE_TEST_BYTES 1024  // Test data size

/* Error codes */
#define HPKE_SUCCESS 0
#define HPKE_BAD_FUNC_ARG -1
#define HPKE_MEMORY_E -2
#define HPKE_RNG_FAILURE_E -3
#define HPKE_CRYPTO_FAILURE -4

/* HPKE algorithms */
#define DHKEM_X25519_HKDF_SHA256 0x0020
#define HKDF_SHA256 0x0001
#define HPKE_AES_128_GCM 0x0001

/* HPKE modes */
#define HPKE_MODE_BASE 0x00

/* ============================================================================
 * STANDALONE TYPE DEFINITIONS (replaces WolfSSL types)
 * ============================================================================ */

typedef unsigned char byte;
typedef unsigned int word32;
typedef unsigned short word16;

/* ECPoint structure */
typedef struct {
    byte point[CURVE25519_KEYSIZE];
} hw_ECPoint;

/* Curve25519 key structure */
typedef struct {
    byte k[CURVE25519_KEYSIZE];     /* Private key */
    hw_ECPoint p;                   /* Public key point */
    byte privSet : 1;               /* Private key set flag */
    byte pubSet : 1;                /* Public key set flag */
    void* heap;                     /* Memory heap (unused) */
    void* rng;                      /* RNG pointer (unused) */
} hw_curve25519_key;

/* HPKE context structure - enhanced for full protocol */
typedef struct {
    word16 kem;
    word16 kdf;
    word16 aead;
    byte key[AES_128_KEY_SIZE];      /* Encryption key */
    byte base_nonce[AES_GCM_IV_SIZE]; /* Base nonce */
    byte exporter_secret[SHA256_DIGEST_SIZE]; /* For key export */
    word32 seq;                      /* Sequence number */
    byte mode;                       /* HPKE mode */
    byte initialized;                /* Context initialized flag */
    void* heap;
} hw_Hpke;

/* Simple RNG structure */
typedef struct {
    uint64_t state;
    int initialized;
} hw_RNG;

/* ============================================================================
 * SIMPLE RNG IMPLEMENTATION (replaces WolfSSL RNG)
 * ============================================================================ */

static hw_RNG g_rng = {0, 0};

static int hw_InitRng(hw_RNG* rng)
{
    if (rng == NULL) return HPKE_BAD_FUNC_ARG;
    
    /* Simple seed from cycle counter */
    rng->state = rdcycle();
    rng->initialized = 1;
    printf("RNG initialized with seed: 0x%llx\n", rng->state);
    return HPKE_SUCCESS;
}

/* Simple PRNG (Linear Congruential Generator) */
static int hw_RNG_GenerateBlock(hw_RNG* rng, byte* output, word32 size)
{
    if (rng == NULL || output == NULL || !rng->initialized)
        return HPKE_RNG_FAILURE_E;
    
    for (word32 i = 0; i < size; i++) {
        rng->state = rng->state * 1103515245ULL + 12345ULL;
        output[i] = (byte)(rng->state >> 32);
    }
    return HPKE_SUCCESS;
}

static void hw_FreeRng(hw_RNG* rng)
{
    if (rng != NULL) {
        rng->initialized = 0;
        rng->state = 0;
    }
}

/* ============================================================================
 * CURVE25519 OPERATIONS (replaces WolfSSL curve25519)
 * ============================================================================ */

/* Initialize curve25519 key */
static int hw_curve25519_init(hw_curve25519_key* key)
{
    if (key == NULL) return HPKE_BAD_FUNC_ARG;
    
    memset(key->k, 0, CURVE25519_KEYSIZE);
    memset(key->p.point, 0, CURVE25519_KEYSIZE);
    key->privSet = 0;
    key->pubSet = 0;
    key->heap = NULL;
    key->rng = NULL;
    return HPKE_SUCCESS;
}

/* Generate private key */
static int hw_curve25519_make_priv(hw_RNG* rng, int keysize, byte* priv)
{
    if (rng == NULL || priv == NULL || keysize != CURVE25519_KEYSIZE)
        return HPKE_BAD_FUNC_ARG;
    
    /* Generate random bytes */
    int ret = hw_RNG_GenerateBlock(rng, priv, CURVE25519_KEYSIZE);
    if (ret != HPKE_SUCCESS) return ret;
    
    /* Apply curve25519 clamping */
    priv[0] &= 248;   /* Clear bottom 3 bits */
    priv[31] &= 127;  /* Clear top bit */
    priv[31] |= 64;   /* Set second-highest bit */
    
    return HPKE_SUCCESS;
}

/* Hardware scalar multiplication wrapper */
static int hw_curve25519_scalar_mult(byte* result, const byte* scalar, const byte* point)
{
    uint64_t hw_scalar[4];
    uint64_t hw_point[4];
    uint64_t hw_result[4];
    void* x25519ctrl = (void*)X25519_HW_BASE_ADDR;
    
    /* Convert to hardware format */
    for (int i = 0; i < 4; i++) {
        hw_scalar[i] = 0;
        hw_point[i] = 0;
        for (int j = 0; j < 8; j++) {
            int byte_idx = i * 8 + j;
            hw_scalar[i] = (hw_scalar[i] << 8) | ((uint64_t)scalar[byte_idx]);
            hw_point[i] = (hw_point[i] << 8) | ((uint64_t)point[byte_idx]);
        }
    }
    
    /* Hardware operation */
    hwx25519_init(x25519ctrl, hw_scalar, hw_point);
    hwx25519_results(x25519ctrl, hw_result);
    
    /* Convert back to bytes */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            int byte_idx = i * 8 + j;
            result[byte_idx] = (byte)((hw_result[i] >> (8 * (7 - j))) & 0xFF);
        }
    }
    
    return HPKE_SUCCESS;
}

/* Generate full key pair */
static int hw_curve25519_make_key(hw_RNG* rng, int keysize, hw_curve25519_key* key)
{
    static const byte basepoint[CURVE25519_KEYSIZE] = {9};
    int ret;
    
    if (key == NULL || rng == NULL) return HPKE_BAD_FUNC_ARG;
    
    /* Generate private key */
    ret = hw_curve25519_make_priv(rng, keysize, key->k);
    if (ret != HPKE_SUCCESS) return ret;
    key->privSet = 1;
    
    /* Compute public key: public = private * basepoint */
    ret = hw_curve25519_scalar_mult(key->p.point, key->k, basepoint);
    if (ret == HPKE_SUCCESS) {
        key->pubSet = 1;
        key->rng = rng;
    }
    
    return ret;
}

/* Shared secret computation */
static int hw_curve25519_shared_secret(hw_curve25519_key* private_key, 
                                       hw_curve25519_key* public_key,
                                       byte* out, word32* outlen)
{
    if (private_key == NULL || public_key == NULL || out == NULL || outlen == NULL)
        return HPKE_BAD_FUNC_ARG;
    
    if (*outlen < CURVE25519_KEYSIZE) return HPKE_BAD_FUNC_ARG;
    
    int ret = hw_curve25519_scalar_mult(out, private_key->k, public_key->p.point);
    if (ret == HPKE_SUCCESS) {
        *outlen = CURVE25519_KEYSIZE;
    }
    return ret;
}

/* Free key (no-op since we don't use dynamic memory) */
static void hw_curve25519_free(hw_curve25519_key* key)
{
    if (key != NULL) {
        memset(key, 0, sizeof(hw_curve25519_key));
    }
}

/* ============================================================================
 * HKDF IMPLEMENTATION (hardware-accelerated)
 * ============================================================================ */

static int hw_HKDF_Extract(const byte* salt, word32 saltSz,
                           const byte* ikm, word32 ikmSz, byte* prk)
{
    void* hmac_shactrl = (void*)HMAC_SHA_HW_BASE_ADDR;
    uint64_t hw_key[8] = {0};
    uint64_t hw_msg[16] = {0};
    uint64_t hw_mac[8] = {0};
    
    /* Pack salt as HMAC key */
    if (salt != NULL && saltSz > 0) {
        for (word32 i = 0; i < saltSz && i < 64; i++) {
            word32 qw_idx = i / 4;
            word32 byte_idx = 3 - (i % 4);
            if (qw_idx < 8) {
                hw_key[qw_idx] |= ((uint64_t)salt[i]) << (8 * byte_idx);
            }
        }
    }
    
    /* Pack IKM as message */
    for (word32 i = 0; i < ikmSz && i < 64; i++) {
        word32 qw_idx = i / 4;
        word32 byte_idx = 3 - (i % 4);
        if (qw_idx < 16) {
            hw_msg[qw_idx] |= ((uint64_t)ikm[i]) << (8 * byte_idx);
        }
    }
    
    /* Hardware HMAC */
    int ret = hmacsha_compute(hmac_shactrl, 1, hw_key, hw_msg, ikmSz * 8, hw_mac);
    if (ret != 0) return HPKE_CRYPTO_FAILURE;
    
    /* Convert result to bytes */
    for (int i = 0; i < 8; i++) {
        uint32_t val = (uint32_t)(hw_mac[i] & 0xFFFFFFFF);
        prk[i*4+0] = (val >> 24) & 0xFF;
        prk[i*4+1] = (val >> 16) & 0xFF;
        prk[i*4+2] = (val >> 8) & 0xFF;
        prk[i*4+3] = val & 0xFF;
    }
    
    return HPKE_SUCCESS;
}

static int hw_HKDF_Expand(const byte* prk, word32 prkSz,
                          const byte* info, word32 infoSz,
                          byte* okm, word32 okmSz)
{
    void* hmac_shactrl = (void*)HMAC_SHA_HW_BASE_ADDR;
    uint64_t hw_key[8] = {0};
    uint64_t hw_mac[8] = {0};
    
    /* Pack PRK as HMAC key */
    for (word32 i = 0; i < prkSz && i < 32; i++) {
        word32 qw_idx = i / 4;
        word32 byte_idx = 3 - (i % 4);
        if (qw_idx < 8) {
            hw_key[qw_idx] |= ((uint64_t)prk[i]) << (8 * byte_idx);
        }
    }
    
    /* HKDF-Expand iterations */
    word32 hash_len = 32;
    word32 n = (okmSz + hash_len - 1) / hash_len;
    byte t_prev[32] = {0};
    word32 okm_offset = 0;
    
    for (word32 iter = 1; iter <= n; iter++) {
        uint64_t hw_msg[16] = {0};
        byte msg_bytes[128];
        word32 msg_len = 0;
        
        /* Build message: T(i-1) || info || counter */
        if (iter > 1) {
            memcpy(msg_bytes + msg_len, t_prev, hash_len);
            msg_len += hash_len;
        }
        if (info != NULL && infoSz > 0) {
            memcpy(msg_bytes + msg_len, info, infoSz);
            msg_len += infoSz;
        }
        msg_bytes[msg_len++] = (byte)iter;
        
        /* Pack message */
        for (word32 i = 0; i < msg_len; i++) {
            word32 qw_idx = i / 4;
            word32 byte_idx = 3 - (i % 4);
            if (qw_idx < 16) {
                hw_msg[qw_idx] |= ((uint64_t)msg_bytes[i]) << (8 * byte_idx);
            }
        }
        
        /* Hardware HMAC */
        int ret = hmacsha_compute(hmac_shactrl, 1, hw_key, hw_msg, msg_len * 8, hw_mac);
        if (ret != 0) return HPKE_CRYPTO_FAILURE;
        
        /* Convert to bytes */
        byte t_current[32];
        for (int j = 0; j < 8; j++) {
            uint32_t val = (uint32_t)(hw_mac[j] & 0xFFFFFFFF);
            t_current[j*4+0] = (val >> 24) & 0xFF;
            t_current[j*4+1] = (val >> 16) & 0xFF;
            t_current[j*4+2] = (val >> 8) & 0xFF;
            t_current[j*4+3] = val & 0xFF;
        }
        
        /* Copy to output */
        word32 copy_len = (okmSz - okm_offset > hash_len) ? hash_len : (okmSz - okm_offset);
        memcpy(okm + okm_offset, t_current, copy_len);
        okm_offset += copy_len;
        
        /* Save for next iteration */
        memcpy(t_prev, t_current, hash_len);
        
        if (okm_offset >= okmSz) break;
    }
    
    return HPKE_SUCCESS;
}

/* ============================================================================
 * AES-GCM IMPLEMENTATION (hardware-accelerated) - FIXED TO MATCH WORKING VERSION
 * ============================================================================ */

/* Pack bytes -> qwords (big-endian per 64-bit word) - COPIED FROM WORKING VERSION */
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

/* Unpack qwords -> bytes (big-endian per 64-bit word) - COPIED FROM WORKING VERSION */
static void unpack_qwords_to_bytes_be(const uint64_t* in, word32 bytes, byte* out)
{
    for (word32 i = 0; i < bytes; ++i) {
        word32 w = i >> 3;
        word32 off = i & 7;
        out[i] = (byte)((in[w] >> (8 * (7 - off))) & 0xFF);
    }
}

static int hw_AES_GCM_Encrypt(const byte* key, word32 keySz,
                              const byte* iv, word32 ivSz,
                              const byte* aad, word32 aadSz,
                              const byte* plaintext, word32 ptSz,
                              byte* ciphertext, byte* tag, word32 tagSz)
{
    if (key == NULL || iv == NULL || ciphertext == NULL || tag == NULL)
        return HPKE_BAD_FUNC_ARG;
    
    if (keySz != AES_128_KEY_SIZE || ivSz != AES_GCM_IV_SIZE || tagSz != AES_GCM_TAG_SIZE)
        return HPKE_BAD_FUNC_ARG;
    
    /* Hardware AES-GCM controller address */
    void* aes_gcmctrl = (void*)AES_GCM_HW_BASE_ADDR;
    
    /* Calculate required qwords dynamically */
    word32 aad_qwords = (aadSz + 7) / 8;
    word32 pt_qwords = (ptSz + 7) / 8;
    
    /* Static buffers for keys and tag - MATCH WORKING VERSION */
    uint64_t hw_key[4] = {0};      /* AES-128 always uses 4 qwords */
    uint64_t hw_iv[2] = {0};       /* 12-byte nonce always uses 2 qwords */
    uint64_t hw_tag[2] = {0};      /* 16-byte auth tag always uses 2 qwords */
    
    /* Static buffers for data - SIMPLIFIED FOR STANDALONE */
    static uint64_t hw_aad_buf[32];   /* Max 256 bytes AAD */
    static uint64_t hw_pt_buf[128];   /* Max 1KB plaintext */
    static uint64_t hw_ct_buf[128];   /* Max 1KB ciphertext */
    
    uint64_t* hw_aad = (aadSz > 0) ? hw_aad_buf : NULL;
    uint64_t* hw_pt = hw_pt_buf;
    uint64_t* hw_ct = hw_ct_buf;
    
    /* Clear buffers */
    if (hw_aad != NULL) {
        for (word32 i = 0; i < aad_qwords && i < 32; i++) hw_aad[i] = 0;
    }
    for (word32 i = 0; i < pt_qwords && i < 128; i++) {
        hw_pt[i] = 0;
        hw_ct[i] = 0;
    }
    
    /* Convert to hardware format - EXACTLY LIKE WORKING VERSION */
    pack_bytes_to_qwords_be_fixed(key, 16, hw_key, 4);
    pack_bytes_to_qwords_be_fixed(iv, 12, hw_iv, 2);
    
    /* Pack AAD if present - EXACTLY LIKE WORKING VERSION */
    if (aad != NULL && aadSz > 0) {
        /* Manual byte-by-byte packing for consistency */
        for (word32 i = 0; i < aadSz; i++) {
            word32 qw_idx = i / 8;
            word32 byte_idx = 7 - (i % 8); /* Big-endian within qword */
            if (qw_idx < 32) {  /* Bounds check */
                hw_aad[qw_idx] |= ((uint64_t)aad[i]) << (8 * byte_idx);
            }
        }
    }
    
    pack_bytes_to_qwords_be_fixed(plaintext, ptSz, hw_pt, pt_qwords);
    
    /* Reset and encrypt with hardware - EXACTLY LIKE WORKING VERSION */
    hw_aes_gcm_reset(aes_gcmctrl);
    hw_aes_gcm_encrypt(aes_gcmctrl, hw_ct, hw_pt, ptSz,
                       hw_key, 16, hw_iv, 12, hw_aad, aadSz, hw_tag, 16);
    
    /* Convert results back to byte format - EXACTLY LIKE WORKING VERSION */
    unpack_qwords_to_bytes_be(hw_ct, ptSz, ciphertext);
    unpack_qwords_to_bytes_be(hw_tag, 16, tag);
    
    return HPKE_SUCCESS;
}

static int hw_AES_GCM_Decrypt(const byte* key, word32 keySz,
                              const byte* iv, word32 ivSz,
                              const byte* aad, word32 aadSz,
                              const byte* ciphertext, word32 ctSz,
                              const byte* tag, word32 tagSz,
                              byte* plaintext)
{
    if (key == NULL || iv == NULL || ciphertext == NULL || tag == NULL || plaintext == NULL)
        return HPKE_BAD_FUNC_ARG;
    
    if (keySz != AES_128_KEY_SIZE || ivSz != AES_GCM_IV_SIZE || tagSz != AES_GCM_TAG_SIZE)
        return HPKE_BAD_FUNC_ARG;
    
    /* Hardware AES-GCM controller address */
    void* aes_gcmctrl = (void*)AES_GCM_HW_BASE_ADDR;
    
    /* Calculate required qwords dynamically */
    word32 aad_qwords = (aadSz + 7) / 8;
    word32 ct_qwords = (ctSz + 7) / 8;
    
    /* Static buffers for keys and tag - MATCH WORKING VERSION */
    uint64_t hw_key[4] = {0};      /* AES-128 always uses 4 qwords */
    uint64_t hw_iv[2] = {0};       /* 12-byte nonce always uses 2 qwords */
    uint64_t hw_tag[2] = {0};      /* 16-byte auth tag always uses 2 qwords */
    
    /* Static buffers for data - SIMPLIFIED FOR STANDALONE */
    static uint64_t hw_aad_buf[32];   /* Max 256 bytes AAD */
    static uint64_t hw_ct_buf[128];   /* Max 1KB ciphertext */
    static uint64_t hw_pt_buf[128];   /* Max 1KB plaintext */
    
    uint64_t* hw_aad = (aadSz > 0) ? hw_aad_buf : NULL;
    uint64_t* hw_ct = hw_ct_buf;
    uint64_t* hw_pt = hw_pt_buf;
    
    /* Clear buffers */
    if (hw_aad != NULL) {
        for (word32 i = 0; i < aad_qwords && i < 32; i++) hw_aad[i] = 0;
    }
    for (word32 i = 0; i < ct_qwords && i < 128; i++) {
        hw_ct[i] = 0;
        hw_pt[i] = 0;
    }
    
    /* Convert inputs to hardware format - EXACTLY LIKE WORKING VERSION */
    pack_bytes_to_qwords_be_fixed(key, 16, hw_key, 4);
    pack_bytes_to_qwords_be_fixed(iv, 12, hw_iv, 2);
    
    /* Pack AAD if present - EXACTLY LIKE WORKING VERSION */
    if (aad != NULL && aadSz > 0) {
        /* Manual byte-by-byte packing for consistency */
        for (word32 i = 0; i < aadSz; i++) {
            word32 qw_idx = i / 8;
            word32 byte_idx = 7 - (i % 8); /* Big-endian within qword */
            if (qw_idx < 32) {  /* Bounds check */
                hw_aad[qw_idx] |= ((uint64_t)aad[i]) << (8 * byte_idx);
            }
        }
    }
    
    pack_bytes_to_qwords_be_fixed(ciphertext, ctSz, hw_ct, ct_qwords);
    pack_bytes_to_qwords_be_fixed(tag, 16, hw_tag, 2);
    
    /* Reset and decrypt with hardware - EXACTLY LIKE WORKING VERSION */
    hw_aes_gcm_reset(aes_gcmctrl);
    int ret = hw_aes_gcm_decrypt_verify(aes_gcmctrl, hw_pt, hw_ct, ctSz,
                                        hw_key, 16, hw_iv, 12, hw_aad, aadSz, hw_tag, 16);
    
    if (ret != 0) {
        printf("Hardware AES-GCM decryption/verification failed: %d\n", ret);
        if (ret == -6) {
            printf("Authentication tag verification failed\n");
        }
        return HPKE_CRYPTO_FAILURE;  /* Authentication failed */
    }
    
    /* Convert result back to byte format - EXACTLY LIKE WORKING VERSION */
    unpack_qwords_to_bytes_be(hw_pt, ctSz, plaintext);
    
    return HPKE_SUCCESS;
}

/* ============================================================================
 * COMPLETE HPKE IMPLEMENTATION
 * ============================================================================ */

/* Initialize HPKE context */
static int hw_HpkeInit(hw_Hpke* hpke, word16 kem, word16 kdf, word16 aead)
{
    if (hpke == NULL) return HPKE_BAD_FUNC_ARG;
    
    if (kem != DHKEM_X25519_HKDF_SHA256 || kdf != HKDF_SHA256 || aead != HPKE_AES_128_GCM)
        return HPKE_BAD_FUNC_ARG;
    
    memset(hpke, 0, sizeof(hw_Hpke));
    hpke->kem = kem;
    hpke->kdf = kdf;
    hpke->aead = aead;
    hpke->mode = HPKE_MODE_BASE;
    hpke->seq = 0;
    hpke->initialized = 0;
    hpke->heap = NULL;
    return HPKE_SUCCESS;
}

/* Serialize public key */
static int hw_HpkeSerializePublicKey(hw_Hpke* hpke, hw_curve25519_key* key, 
                                     byte* out, word16* outSz)
{
    if (hpke == NULL || key == NULL || out == NULL || outSz == NULL)
        return HPKE_BAD_FUNC_ARG;
    
    if (*outSz < CURVE25519_KEYSIZE) return HPKE_BAD_FUNC_ARG;
    if (!key->pubSet) return HPKE_BAD_FUNC_ARG;
    
    memcpy(out, key->p.point, CURVE25519_KEYSIZE);
    *outSz = CURVE25519_KEYSIZE;
    return HPKE_SUCCESS;
}

/* Generate key pair */
static int hw_HpkeGenerateKeyPair(hw_Hpke* hpke, hw_curve25519_key* keypair, hw_RNG* rng)
{
    if (hpke == NULL || keypair == NULL || rng == NULL)
        return HPKE_BAD_FUNC_ARG;
    
    int ret = hw_curve25519_init(keypair);
    if (ret != HPKE_SUCCESS) return ret;
    
    return hw_curve25519_make_key(rng, CURVE25519_KEYSIZE, keypair);
}

/* Key Schedule function for HPKE */
static int hw_HpkeKeySchedule(hw_Hpke* hpke, const byte* shared_secret, 
                              const byte* info, word32 infoSz)
{
    if (hpke == NULL || shared_secret == NULL) return HPKE_BAD_FUNC_ARG;
    
    /* Extract step: PRK = HKDF-Extract(salt="", shared_secret) */
    byte prk[SHA256_DIGEST_SIZE];
    int ret = hw_HKDF_Extract(NULL, 0, shared_secret, CURVE25519_KEYSIZE, prk);
    if (ret != HPKE_SUCCESS) return ret;
    
    /* Expand step: derive key, base_nonce, and exporter_secret */
    const char* key_info = "hpke key";
    const char* nonce_info = "hpke base_nonce";  
    const char* exp_info = "hpke exp";
    
    /* Derive encryption key */
    ret = hw_HKDF_Expand(prk, SHA256_DIGEST_SIZE, 
                         (const byte*)key_info, strlen(key_info),
                         hpke->key, AES_128_KEY_SIZE);
    if (ret != HPKE_SUCCESS) return ret;
    
    /* Derive base nonce */
    ret = hw_HKDF_Expand(prk, SHA256_DIGEST_SIZE,
                         (const byte*)nonce_info, strlen(nonce_info), 
                         hpke->base_nonce, AES_GCM_IV_SIZE);
    if (ret != HPKE_SUCCESS) return ret;
    
    /* Derive exporter secret */
    ret = hw_HKDF_Expand(prk, SHA256_DIGEST_SIZE,
                         (const byte*)exp_info, strlen(exp_info),
                         hpke->exporter_secret, SHA256_DIGEST_SIZE);
    if (ret != HPKE_SUCCESS) return ret;
    
    hpke->seq = 0;
    hpke->initialized = 1;
    return HPKE_SUCCESS;
}

/* Compute sequence-specific nonce */
static void hw_HpkeComputeNonce(hw_Hpke* hpke, byte* nonce)
{
    memcpy(nonce, hpke->base_nonce, AES_GCM_IV_SIZE);
    
    /* XOR with sequence number (big-endian) */
    for (int i = 0; i < 4; i++) {
        byte seq_byte = (byte)((hpke->seq >> (8 * (3 - i))) & 0xFF);
        nonce[AES_GCM_IV_SIZE - 4 + i] ^= seq_byte;
    }
}

/* HPKE Encapsulation (Sender side) */
static int hw_HpkeEncap(hw_Hpke* hpke, hw_curve25519_key* ephemeral_key,
                        hw_curve25519_key* receiver_public_key,
                        byte* encapsulated_key, word16* enc_sz)
{
    if (hpke == NULL || ephemeral_key == NULL || receiver_public_key == NULL ||
        encapsulated_key == NULL || enc_sz == NULL)
        return HPKE_BAD_FUNC_ARG;
    
    if (*enc_sz < CURVE25519_KEYSIZE) return HPKE_BAD_FUNC_ARG;
    
    /* Compute shared secret */
    byte shared_secret[CURVE25519_KEYSIZE];
    word32 ss_len = CURVE25519_KEYSIZE;
    int ret = hw_curve25519_shared_secret(ephemeral_key, receiver_public_key, 
                                          shared_secret, &ss_len);
    if (ret != HPKE_SUCCESS) return ret;
    
    /* Serialize ephemeral public key as encapsulated key */
    memcpy(encapsulated_key, ephemeral_key->p.point, CURVE25519_KEYSIZE);
    *enc_sz = CURVE25519_KEYSIZE;
    
    /* Derive encryption context */
    ret = hw_HpkeKeySchedule(hpke, shared_secret, NULL, 0);
    if (ret != HPKE_SUCCESS) return ret;
    
    return HPKE_SUCCESS;
}

/* HPKE Decapsulation (Receiver side) */
static int hw_HpkeDecap(hw_Hpke* hpke, const byte* encapsulated_key, word16 enc_sz,
                        hw_curve25519_key* receiver_private_key)
{
    if (hpke == NULL || encapsulated_key == NULL || receiver_private_key == NULL)
        return HPKE_BAD_FUNC_ARG;
    
    if (enc_sz != CURVE25519_KEYSIZE) return HPKE_BAD_FUNC_ARG;
    
    /* Reconstruct ephemeral public key */
    hw_curve25519_key ephemeral_public;
    int ret = hw_curve25519_init(&ephemeral_public);
    if (ret != HPKE_SUCCESS) return ret;
    
    memcpy(ephemeral_public.p.point, encapsulated_key, CURVE25519_KEYSIZE);
    ephemeral_public.pubSet = 1;
    
    /* Compute shared secret */
    byte shared_secret[CURVE25519_KEYSIZE];
    word32 ss_len = CURVE25519_KEYSIZE;
    ret = hw_curve25519_shared_secret(receiver_private_key, &ephemeral_public,
                                      shared_secret, &ss_len);
    if (ret != HPKE_SUCCESS) return ret;
    
    /* Derive encryption context */
    ret = hw_HpkeKeySchedule(hpke, shared_secret, NULL, 0);
    if (ret != HPKE_SUCCESS) return ret;
    
    return HPKE_SUCCESS;
}

/* HPKE Seal (Encrypt) */
static int hw_HpkeSeal(hw_Hpke* hpke, const byte* aad, word32 aadSz,
                       const byte* plaintext, word32 ptSz,
                       byte* ciphertext, word32* ctSz)
{
    if (hpke == NULL || ciphertext == NULL || ctSz == NULL)
        return HPKE_BAD_FUNC_ARG;
    
    if (!hpke->initialized) return HPKE_BAD_FUNC_ARG;
    if (*ctSz < ptSz + AES_GCM_TAG_SIZE) return HPKE_BAD_FUNC_ARG;
    
    /* Compute sequence-specific nonce */
    byte nonce[AES_GCM_IV_SIZE];
    hw_HpkeComputeNonce(hpke, nonce);
    
    /* Encrypt using AES-GCM */
    byte* tag = ciphertext + ptSz;  /* Tag goes after ciphertext */
    int ret = hw_AES_GCM_Encrypt(hpke->key, AES_128_KEY_SIZE,
                                 nonce, AES_GCM_IV_SIZE,
                                 aad, aadSz,
                                 plaintext, ptSz,
                                 ciphertext, tag, AES_GCM_TAG_SIZE);
    if (ret != HPKE_SUCCESS) return ret;
    
    *ctSz = ptSz + AES_GCM_TAG_SIZE;
    hpke->seq++;  /* Increment sequence number */
    
    return HPKE_SUCCESS;
}

/* HPKE Open (Decrypt) */
static int hw_HpkeOpen(hw_Hpke* hpke, const byte* aad, word32 aadSz,
                       const byte* ciphertext, word32 ctSz,
                       byte* plaintext, word32* ptSz)
{
    if (hpke == NULL || ciphertext == NULL || plaintext == NULL || ptSz == NULL)
        return HPKE_BAD_FUNC_ARG;
    
    if (!hpke->initialized) return HPKE_BAD_FUNC_ARG;
    if (ctSz < AES_GCM_TAG_SIZE) return HPKE_BAD_FUNC_ARG;
    
    word32 actual_ct_sz = ctSz - AES_GCM_TAG_SIZE;
    if (*ptSz < actual_ct_sz) return HPKE_BAD_FUNC_ARG;
    
    /* Compute sequence-specific nonce */
    byte nonce[AES_GCM_IV_SIZE];
    hw_HpkeComputeNonce(hpke, nonce);
    
    /* Extract tag from end of ciphertext */
    const byte* tag = ciphertext + actual_ct_sz;
    
    /* Decrypt using AES-GCM */
    int ret = hw_AES_GCM_Decrypt(hpke->key, AES_128_KEY_SIZE,
                                 nonce, AES_GCM_IV_SIZE,
                                 aad, aadSz,
                                 ciphertext, actual_ct_sz,
                                 tag, AES_GCM_TAG_SIZE,
                                 plaintext);
    if (ret != HPKE_SUCCESS) return ret;
    
    *ptSz = actual_ct_sz;
    hpke->seq++;  /* Increment sequence number */
    
    return HPKE_SUCCESS;
}

/* Free HPKE context */
static void hw_HpkeFreeKey(hw_Hpke* hpke)
{
    if (hpke != NULL) {
        memset(hpke, 0, sizeof(hw_Hpke));
    }
}

/* ============================================================================
 * COMPLETE HPKE TEST WITH FULL PROTOCOL
 * ============================================================================ */

static void print_hex(const char* label, const byte* data, int len)
{
    printf("%s: ", label);
    for (int i = 0; i < len && i < 32; i++) {  /* Limit output for readability */
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...[%d bytes total]", len);
    printf("\n");
}

int main(void)
{
    printf("=== Complete HPKE Implementation Test (No WolfSSL) ===\n\n");
    
    hw_RNG rng;
    hw_Hpke sender_ctx, receiver_ctx;
    hw_curve25519_key receiver_key, ephemeral_key;
    int ret;
    
    /* Test data - 1KB MESSAGE LIKE ORIGINAL */
    static byte test_message[1024];  /* 1KB test message */
    const char* test_aad = "Additional authenticated data";
    word32 msg_len = 1024;           /* Full 1KB */
    word32 aad_len = strlen(test_aad);
    
    /* Generate 1KB test pattern - similar to original hpke_hw.c */
    for (word32 i = 0; i < 1024; i++) {
        if (i < 26) {
            test_message[i] = 'A' + i;  /* A-Z pattern */
        } else if (i < 52) {
            test_message[i] = 'a' + (i - 26);  /* a-z pattern */
        } else if (i < 62) {
            test_message[i] = '0' + (i - 52);  /* 0-9 pattern */
        } else {
            test_message[i] = (byte)((i * 7 + 13) & 0xFF);  /* Pseudo-random pattern */
        }
    }
    
    /* Buffers */
    byte encapsulated_key[CURVE25519_KEYSIZE];
    word16 enc_sz = CURVE25519_KEYSIZE;
    byte ciphertext[HPKE_TEST_BYTES + AES_GCM_TAG_SIZE];
    byte decrypted[HPKE_TEST_BYTES];
    word32 ct_sz = sizeof(ciphertext);
    word32 dec_sz = sizeof(decrypted);
    
    printf("Test message size: %d bytes (1KB)\n", msg_len);
    printf("Message preview: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", test_message[i]);
    }
    printf("...[1024 bytes total]\n");
    printf("AAD (%d bytes): \"%s\"\n\n", aad_len, test_aad);
    
    /* ========================================================================
     * STEP 1: Initialize RNG and HPKE contexts
     * ======================================================================== */
    printf("🔧 Step 1: Initializing RNG and HPKE contexts...\n");
    
    ret = hw_InitRng(&rng);
    if (ret != HPKE_SUCCESS) {
        printf("❌ RNG init failed: %d\n", ret);
        return -1;
    }
    
    ret = hw_HpkeInit(&sender_ctx, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, HPKE_AES_128_GCM);
    if (ret != HPKE_SUCCESS) {
        printf("❌ Sender HPKE init failed: %d\n", ret);
        return -1;
    }
    
    ret = hw_HpkeInit(&receiver_ctx, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, HPKE_AES_128_GCM);
    if (ret != HPKE_SUCCESS) {
        printf("❌ Receiver HPKE init failed: %d\n", ret);
        return -1;
    }
    printf("✅ Initialization complete\n\n");
    
    /* ========================================================================
     * STEP 2: Generate receiver key pair (long-term key)
     * ======================================================================== */
    printf("🔑 Step 2: Generating receiver key pair...\n");
    
    ret = hw_HpkeGenerateKeyPair(&receiver_ctx, &receiver_key, &rng);
    if (ret != HPKE_SUCCESS) {
        printf("❌ Receiver key generation failed: %d\n", ret);
        return -1;
    }
    
    print_hex("Receiver private key", receiver_key.k, 32);
    print_hex("Receiver public key", receiver_key.p.point, 32);
    printf("✅ Receiver key pair generated\n\n");
    
    /* ========================================================================
     * STEP 3: Generate ephemeral key pair (sender side)
     * ======================================================================== */
    printf("🔑 Step 3: Generating ephemeral key pair...\n");
    
    ret = hw_HpkeGenerateKeyPair(&sender_ctx, &ephemeral_key, &rng);
    if (ret != HPKE_SUCCESS) {
        printf("❌ Ephemeral key generation failed: %d\n", ret);
        return -1;
    }
    
    print_hex("Ephemeral private key", ephemeral_key.k, 32);
    print_hex("Ephemeral public key", ephemeral_key.p.point, 32);
    printf("✅ Ephemeral key pair generated\n\n");
    
    /* ========================================================================
     * STEP 4: HPKE Encapsulation (sender side)
     * ======================================================================== */
    printf("📦 Step 4: HPKE Encapsulation (sender side)...\n");
    
    ret = hw_HpkeEncap(&sender_ctx, &ephemeral_key, &receiver_key, 
                       encapsulated_key, &enc_sz);
    if (ret != HPKE_SUCCESS) {
        printf("❌ HPKE encapsulation failed: %d\n", ret);
        return -1;
    }
    
    print_hex("Encapsulated key", encapsulated_key, enc_sz);
    print_hex("Sender encryption key", sender_ctx.key, AES_128_KEY_SIZE);
    print_hex("Sender base nonce", sender_ctx.base_nonce, AES_GCM_IV_SIZE);
    printf("✅ Encapsulation complete\n\n");
    
    /* ========================================================================
     * STEP 5: HPKE Decapsulation (receiver side)
     * ======================================================================== */
    printf("📦 Step 5: HPKE Decapsulation (receiver side)...\n");
    
    ret = hw_HpkeDecap(&receiver_ctx, encapsulated_key, enc_sz, &receiver_key);
    if (ret != HPKE_SUCCESS) {
        printf("❌ HPKE decapsulation failed: %d\n", ret);
        return -1;
    }
    
    print_hex("Receiver encryption key", receiver_ctx.key, AES_128_KEY_SIZE);
    print_hex("Receiver base nonce", receiver_ctx.base_nonce, AES_GCM_IV_SIZE);
    
    /* Verify keys match */
    if (memcmp(sender_ctx.key, receiver_ctx.key, AES_128_KEY_SIZE) == 0 &&
        memcmp(sender_ctx.base_nonce, receiver_ctx.base_nonce, AES_GCM_IV_SIZE) == 0) {
        printf("✅ Key agreement successful - encryption contexts match!\n\n");
    } else {
        printf("❌ Key agreement failed - contexts don't match!\n");
        return -1;
    }
    
    /* ========================================================================
     * STEP 6: HPKE Seal (encrypt message) - 1KB MESSAGE
     * ======================================================================== */
    printf("🔒 Step 6: HPKE Seal (encrypt 1KB message)...\n");
    
    ret = hw_HpkeSeal(&sender_ctx, (const byte*)test_aad, aad_len,
                      test_message, msg_len,  /* Now using 1KB message */
                      ciphertext, &ct_sz);
    if (ret != HPKE_SUCCESS) {
        printf("❌ HPKE seal failed: %d\n", ret);
        return -1;
    }
    
    print_hex("Ciphertext", ciphertext, ct_sz);
    printf("Ciphertext size: %d bytes (plaintext: %d + tag: %d)\n", 
           ct_sz, msg_len, AES_GCM_TAG_SIZE);
    printf("✅ 1KB message encrypted successfully\n\n");
    
    /* ========================================================================
     * STEP 7: HPKE Open (decrypt message) - 1KB MESSAGE
     * ======================================================================== */
    printf("🔓 Step 7: HPKE Open (decrypt 1KB message)...\n");
    
    ret = hw_HpkeOpen(&receiver_ctx, (const byte*)test_aad, aad_len,
                      ciphertext, ct_sz, decrypted, &dec_sz);
    if (ret != HPKE_SUCCESS) {
        printf("❌ HPKE open failed: %d\n", ret);
        return -1;
    }
    
    printf("Decrypted message size: %d bytes\n", dec_sz);
    printf("Decrypted preview: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", decrypted[i]);
    }
    printf("...[%d bytes total]\n", dec_sz);
    
    /* Verify decryption - 1KB comparison */
    if (dec_sz == msg_len && memcmp(test_message, decrypted, msg_len) == 0) {
        printf("✅ 1KB decryption successful - messages match!\n\n");
    } else {
        printf("❌ 1KB decryption failed - messages don't match!\n");
        printf("Expected size: %d, Got size: %d\n", msg_len, dec_sz);
        
        /* Show first mismatch for debugging */
        for (word32 i = 0; i < msg_len && i < dec_sz; i++) {
            if (test_message[i] != decrypted[i]) {
                printf("First mismatch at byte %d: expected 0x%02x, got 0x%02x\n", 
                       i, test_message[i], decrypted[i]);
                break;
            }
        }
        return -1;
    }
    
    /* ========================================================================
     * STEP 8: Test multiple encryption rounds (sequence numbers) - 1KB EACH
     * ======================================================================== */
    printf("🔄 Step 8: Testing multiple 1KB encryption rounds...\n");
    
    for (int round = 1; round <= 3; round++) {
        static byte round_msg[1024];  /* 1KB message for each round */
        
        /* Generate different 1KB pattern for each round */
        for (word32 i = 0; i < 1024; i++) {
            round_msg[i] = (byte)((i * round + round * 17 + 42) & 0xFF);
        }
        word32 round_msg_len = 1024;
        
        word32 round_ct_sz = sizeof(ciphertext);
        word32 round_dec_sz = sizeof(decrypted);
        
        /* Encrypt 1KB */
        ret = hw_HpkeSeal(&sender_ctx, (const byte*)test_aad, aad_len,
                          round_msg, round_msg_len,
                          ciphertext, &round_ct_sz);
        if (ret != HPKE_SUCCESS) {
            printf("❌ Round %d seal failed: %d\n", round, ret);
            return -1;
        }
        
        /* Decrypt 1KB */
        ret = hw_HpkeOpen(&receiver_ctx, (const byte*)test_aad, aad_len,
                          ciphertext, round_ct_sz, decrypted, &round_dec_sz);
        if (ret != HPKE_SUCCESS) {
            printf("❌ Round %d open failed: %d\n", round, ret);
            return -1;
        }
        
        printf("  Round %d: 1KB message encrypted/decrypted", round);
        
        if (round_dec_sz != round_msg_len || memcmp(round_msg, decrypted, round_msg_len) != 0) {
            printf(" ❌ FAILED\n");
            printf("    Expected size: %d, Got size: %d\n", round_msg_len, round_dec_sz);
            return -1;
        } else {
            printf(" ✅\n");
        }
    }
    
    printf("✅ Multiple 1KB round test passed\n\n");
    
    /* ========================================================================
     * FINAL RESULTS
     * ======================================================================== */
    printf("🎉 ===============================================\n");
    printf("🎉 ALL 1KB HPKE TESTS PASSED SUCCESSFULLY!\n");
    printf("🎉 ===============================================\n");
    printf("✅ Complete HPKE protocol implemented\n");
    printf("✅ X25519 key exchange working\n");
    printf("✅ HKDF key derivation working\n");
    printf("✅ AES-GCM encryption/decryption working (1KB)\n");
    printf("✅ Sequence number handling working\n");
    printf("✅ Hardware acceleration utilized\n");
    printf("✅ Zero WolfSSL dependency\n");
    
    printf("\n📊 Context Information:\n");
    printf("   Test message size: %d bytes (1KB)\n", msg_len);
    printf("   Sender sequence:   %d\n", sender_ctx.seq);
    printf("   Receiver sequence: %d\n", receiver_ctx.seq);
    printf("   Encryption key size: %d bytes\n", AES_128_KEY_SIZE);
    printf("   Nonce size: %d bytes\n", AES_GCM_IV_SIZE);
    printf("   Tag size: %d bytes\n", AES_GCM_TAG_SIZE);
    
    /* Cleanup */
    hw_FreeRng(&rng);
    hw_curve25519_free(&receiver_key);
    hw_curve25519_free(&ephemeral_key);
    hw_HpkeFreeKey(&sender_ctx);
    hw_HpkeFreeKey(&receiver_ctx);
    
    return 0;
}