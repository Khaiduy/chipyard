/* ascon_hkdf.c
 *
 * Implementation of HKDF using Ascon hash function (software)
 * with X25519 and Ascon AEAD hardware support
 */

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/ascon.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define ASCON_HASH_SIZE 32
#define ASCON_BLOCK_SIZE 64

/* HMAC using Ascon hash (software implementation) */
typedef struct {
    AsconHash hash;
    byte ipad[ASCON_BLOCK_SIZE];
    byte opad[ASCON_BLOCK_SIZE];
    byte innerHash[ASCON_HASH_SIZE];
    byte macType;
} AsconHmac;

/* Initialize Ascon HMAC */
static int wc_AsconHmacInit(AsconHmac* hmac)
{
    if (hmac == NULL)
        return BAD_FUNC_ARG;
    
    XMEMSET(hmac, 0, sizeof(AsconHmac));
    return 0;
}

/* Set key for Ascon HMAC */
static int wc_AsconHmacSetKey(AsconHmac* hmac, const byte* key, word32 keySz)
{
    int ret;
    byte keyHash[ASCON_HASH_SIZE];
    const byte* keyPtr = key;
    word32 keyLen = keySz;
    int i;
    
    if (hmac == NULL || key == NULL)
        return BAD_FUNC_ARG;
    
    /* Hash key if longer than block size */
    if (keySz > ASCON_BLOCK_SIZE) {
        ret = wc_AsconHash(key, keySz, keyHash);
        if (ret != 0)
            return ret;
        keyPtr = keyHash;
        keyLen = ASCON_HASH_SIZE;
    }
    
    /* Create ipad and opad */
    XMEMSET(hmac->ipad, IPAD, ASCON_BLOCK_SIZE);
    XMEMSET(hmac->opad, OPAD, ASCON_BLOCK_SIZE);
    
    for (i = 0; i < (int)keyLen; i++) {
        hmac->ipad[i] ^= keyPtr[i];
        hmac->opad[i] ^= keyPtr[i];
    }
    
    /* Initialize inner hash with ipad */
    ret = wc_InitAsconHash(&hmac->hash);
    if (ret != 0)
        return ret;
    
    ret = wc_AsconHashUpdate(&hmac->hash, hmac->ipad, ASCON_BLOCK_SIZE);
    
    return ret;
}

/* Update Ascon HMAC */
static int wc_AsconHmacUpdate(AsconHmac* hmac, const byte* in, word32 sz)
{
    if (hmac == NULL || (in == NULL && sz > 0))
        return BAD_FUNC_ARG;
    
    return wc_AsconHashUpdate(&hmac->hash, in, sz);
}

/* Finalize Ascon HMAC */
static int wc_AsconHmacFinal(AsconHmac* hmac, byte* out)
{
    int ret;
    AsconHash outerHash;
    
    if (hmac == NULL || out == NULL)
        return BAD_FUNC_ARG;
    
    /* Finalize inner hash */
    ret = wc_AsconHashFinal(&hmac->hash, hmac->innerHash);
    if (ret != 0)
        return ret;
    
    /* Compute outer hash: H(opad || innerHash) */
    ret = wc_InitAsconHash(&outerHash);
    if (ret != 0)
        return ret;
    
    ret = wc_AsconHashUpdate(&outerHash, hmac->opad, ASCON_BLOCK_SIZE);
    if (ret != 0)
        return ret;
    
    ret = wc_AsconHashUpdate(&outerHash, hmac->innerHash, ASCON_HASH_SIZE);
    if (ret != 0)
        return ret;
    
    ret = wc_AsconHashFinal(&outerHash, out);
    
    return ret;
}

/* HKDF Extract using Ascon HMAC (software) */
int wc_HKDF_Extract_Ascon(const byte* salt, word32 saltSz,
                          const byte* inKey, word32 inKeySz, byte* out)
{
    int ret;
    AsconHmac hmac;
    byte defaultSalt[ASCON_HASH_SIZE];
    
    if (inKey == NULL || out == NULL)
        return BAD_FUNC_ARG;
    
    /* Use zero salt if not provided */
    if (salt == NULL || saltSz == 0) {
        XMEMSET(defaultSalt, 0, ASCON_HASH_SIZE);
        salt = defaultSalt;
        saltSz = ASCON_HASH_SIZE;
    }
    
    ret = wc_AsconHmacInit(&hmac);
    if (ret != 0)
        return ret;
    
    ret = wc_AsconHmacSetKey(&hmac, salt, saltSz);
    if (ret != 0)
        return ret;
    
    ret = wc_AsconHmacUpdate(&hmac, inKey, inKeySz);
    if (ret != 0)
        return ret;
    
    ret = wc_AsconHmacFinal(&hmac, out);
    
    return ret;
}

/* HKDF Expand using Ascon HMAC (software) */
int wc_HKDF_Expand_Ascon(const byte* prk, word32 prkSz,
                         const byte* info, word32 infoSz,
                         byte* out, word32 outSz)
{
    int ret;
    AsconHmac hmac;
    byte T[ASCON_HASH_SIZE];
    byte counter = 1;
    word32 i;
    word32 remaining = outSz;
    word32 offset = 0;
    
    if (prk == NULL || out == NULL || outSz == 0)
        return BAD_FUNC_ARG;
    
    /* Check output length limit: N * HashLen */
    if (outSz > (255 * ASCON_HASH_SIZE))
        return BAD_FUNC_ARG;
    
    XMEMSET(T, 0, ASCON_HASH_SIZE);
    
    while (remaining > 0) {
        word32 currentLen = (remaining < ASCON_HASH_SIZE) ? remaining : ASCON_HASH_SIZE;
        
        ret = wc_AsconHmacInit(&hmac);
        if (ret != 0)
            return ret;
        
        ret = wc_AsconHmacSetKey(&hmac, prk, prkSz);
        if (ret != 0)
            return ret;
        
        /* T(i) = HMAC(PRK, T(i-1) | info | i) */
        if (counter > 1) {
            ret = wc_AsconHmacUpdate(&hmac, T, ASCON_HASH_SIZE);
            if (ret != 0)
                return ret;
        }
        
        if (info != NULL && infoSz > 0) {
            ret = wc_AsconHmacUpdate(&hmac, info, infoSz);
            if (ret != 0)
                return ret;
        }
        
        ret = wc_AsconHmacUpdate(&hmac, &counter, 1);
        if (ret != 0)
            return ret;
        
        ret = wc_AsconHmacFinal(&hmac, T);
        if (ret != 0)
            return ret;
        
        XMEMCPY(out + offset, T, currentLen);
        
        offset += currentLen;
        remaining -= currentLen;
        counter++;
    }
    
    return 0;
}

/* X25519 key exchange (hardware accelerated) */
int wc_X25519_KeyExchange(curve25519_key* privateKey, curve25519_key* publicKey,
                          byte* sharedSecret, word32* secretSz)
{
    return wc_curve25519_shared_secret_ex(privateKey, publicKey, 
                                          sharedSecret, secretSz, EC25519_LITTLE_ENDIAN);
}

/* Ascon AEAD encryption (hardware accelerated) */
int wc_AsconAeadEncrypt(const byte* key, word32 keySz,
                        const byte* nonce, word32 nonceSz,
                        const byte* aad, word32 aadSz,
                        const byte* plaintext, word32 plaintextSz,
                        byte* ciphertext, byte* tag, word32 tagSz)
{
    return wc_Ascon128aEncrypt(key, keySz, nonce, nonceSz,
                               aad, aadSz, plaintext, plaintextSz,
                               ciphertext, tag, tagSz);
}

/* Ascon AEAD decryption (hardware accelerated) */
int wc_AsconAeadDecrypt(const byte* key, word32 keySz,
                        const byte* nonce, word32 nonceSz,
                        const byte* aad, word32 aadSz,
                        const byte* ciphertext, word32 ciphertextSz,
                        const byte* tag, word32 tagSz,
                        byte* plaintext)
{
    return wc_Ascon128aDecrypt(key, keySz, nonce, nonceSz,
                               aad, aadSz, ciphertext, ciphertextSz,
                               tag, tagSz, plaintext);
}