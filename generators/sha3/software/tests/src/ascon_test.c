#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "compiler.h"
#include <inttypes.h>
#include <math.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

// ASCON support depends on WolfSSL configuration
#ifdef HAVE_ASCON
#include <wolfssl/wolfcrypt/ascon.h>

int test_ascon_aead128() {
    printf("=== Testing ASCON-128 AEAD ===\n");
    
    // ASCON-128 test vectors
    const char* plaintext = "Hello RISC-V!";
    unsigned char key[ASCON_AEAD128_KEY_SZ] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    unsigned char nonce[ASCON_AEAD128_NONCE_SZ] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    unsigned char aad[] = "RISC-V";
    unsigned char ciphertext[64];
    unsigned char tag[ASCON_AEAD128_TAG_SZ];
    unsigned char decrypted[64];
    
    int plaintext_len = strlen(plaintext);
    int aad_len = strlen((char*)aad);
    
    wc_AsconAEAD128* ascon_enc = NULL;
    wc_AsconAEAD128* ascon_dec = NULL;
    
    // === ENCRYPTION ===
    ascon_enc = wc_AsconAEAD128_New();
    if (ascon_enc == NULL) {
        printf("ASCON AEAD128 new failed\n");
        return -1;
    }
    
    // Set key
    int ret = wc_AsconAEAD128_SetKey(ascon_enc, key);
    if (ret != 0) {
        printf("ASCON set key failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconAEAD128_Free(ascon_enc);
        return -1;
    }
    
    // Set nonce
    ret = wc_AsconAEAD128_SetNonce(ascon_enc, nonce);
    if (ret != 0) {
        printf("ASCON set nonce failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconAEAD128_Free(ascon_enc);
        return -1;
    }
    
    // Set additional data
    ret = wc_AsconAEAD128_SetAD(ascon_enc, aad, aad_len);
    if (ret != 0) {
        printf("ASCON set AD failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconAEAD128_Free(ascon_enc);
        return -1;
    }
    
    // Encrypt
    ret = wc_AsconAEAD128_EncryptUpdate(ascon_enc, ciphertext, (const byte*)plaintext, plaintext_len);
    if (ret != 0) {
        printf("ASCON encrypt update failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconAEAD128_Free(ascon_enc);
        return -1;
    }
    
    // Finalize encryption and get tag
    ret = wc_AsconAEAD128_EncryptFinal(ascon_enc, tag);
    if (ret != 0) {
        printf("ASCON encrypt final failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconAEAD128_Free(ascon_enc);
        return -1;
    }
    
    // Free encryption context
    wc_AsconAEAD128_Free(ascon_enc);
    
    printf("Encryption successful!\n");
    printf("Plaintext:  \"%s\"\n", plaintext);
    printf("Key:        ");
    for (int i = 0; i < ASCON_AEAD128_KEY_SZ; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    
    printf("Nonce:      ");
    for (int i = 0; i < ASCON_AEAD128_NONCE_SZ; i++) {
        printf("%02x", nonce[i]);
    }
    printf("\n");
    
    printf("AAD:        \"%s\"\n", aad);
    
    printf("Ciphertext: ");
    for (int i = 0; i < plaintext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    
    printf("Tag:        ");
    for (int i = 0; i < ASCON_AEAD128_TAG_SZ; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");
    
    // === DECRYPTION ===
    ascon_dec = wc_AsconAEAD128_New();
    if (ascon_dec == NULL) {
        printf("ASCON AEAD128 new (decrypt) failed\n");
        return -1;
    }
    
    // Set key
    ret = wc_AsconAEAD128_SetKey(ascon_dec, key);
    if (ret != 0) {
        printf("ASCON set key (decrypt) failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconAEAD128_Free(ascon_dec);
        return -1;
    }
    
    // Set nonce
    ret = wc_AsconAEAD128_SetNonce(ascon_dec, nonce);
    if (ret != 0) {
        printf("ASCON set nonce (decrypt) failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconAEAD128_Free(ascon_dec);
        return -1;
    }
    
    // Set additional data
    ret = wc_AsconAEAD128_SetAD(ascon_dec, aad, aad_len);
    if (ret != 0) {
        printf("ASCON set AD (decrypt) failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconAEAD128_Free(ascon_dec);
        return -1;
    }
    
    // Decrypt
    ret = wc_AsconAEAD128_DecryptUpdate(ascon_dec, decrypted, ciphertext, plaintext_len);
    if (ret != 0) {
        printf("ASCON decrypt update failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconAEAD128_Free(ascon_dec);
        return -1;
    }
    
    // Verify tag and finalize
    ret = wc_AsconAEAD128_DecryptFinal(ascon_dec, tag);
    if (ret != 0) {
        printf("ASCON decrypt final failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconAEAD128_Free(ascon_dec);
        return -1;
    }
    
    // Free decryption context
    wc_AsconAEAD128_Free(ascon_dec);
    
    // Null terminate decrypted text for printing
    decrypted[plaintext_len] = '\0';
    
    // Verify decryption
    if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("Decrypted:  \"%s\"\n", decrypted);
        printf("ASCON-128 AEAD test PASSED\n");
        return 0;
    } else {
        printf("ASCON-128 AEAD test FAILED - decryption mismatch\n");
        printf("Expected: \"%s\"\n", plaintext);
        printf("Got:      \"%s\"\n", decrypted);
        return -1;
    }
}

int test_ascon_hash256() {
    printf("\n=== Testing ASCON-Hash256 ===\n");
    
    const char* message = "Hello RISC-V!";
    unsigned char hash[ASCON_HASH256_SZ];
    
    wc_AsconHash256* ascon_hash = wc_AsconHash256_New();
    if (ascon_hash == NULL) {
        printf("ASCON Hash256 new failed\n");
        return -1;
    }
    
    // Update with message
    int ret = wc_AsconHash256_Update(ascon_hash, (const byte*)message, strlen(message));
    if (ret != 0) {
        printf("ASCON Hash256 update failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconHash256_Free(ascon_hash);
        return -1;
    }
    
    // Finalize hash
    ret = wc_AsconHash256_Final(ascon_hash, hash);
    if (ret != 0) {
        printf("ASCON Hash256 final failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_AsconHash256_Free(ascon_hash);
        return -1;
    }
    
    // Free hash context
    wc_AsconHash256_Free(ascon_hash);
    
    printf("Hash computation successful!\n");
    printf("Input:  \"%s\"\n", message);
    printf("Hash:   ");
    for (int i = 0; i < ASCON_HASH256_SZ; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    printf("ASCON-Hash256 test PASSED\n");
    
    return 0;
}

#endif // HAVE_ASCON

int main(void) {
    printf("WolfSSL ASCON Test\n");
    printf("==================\n");
    
#ifdef HAVE_ASCON
    unsigned long start, end;
    int result = 0;
    
    // Test ASCON AEAD128
    start = rdcycle();
    int aead_result = test_ascon_aead128();
    end = rdcycle();
    printf("ASCON-128 AEAD execution took %lu cycles\n", end - start);
    
    if (aead_result != 0) {
        result = -1;
    }
    
    // Test ASCON Hash256
    start = rdcycle();
    int hash_result = test_ascon_hash256();
    end = rdcycle();
    printf("ASCON-Hash256 execution took %lu cycles\n", end - start);
    
    if (hash_result != 0) {
        result = -1;
    }
    
    printf("==================\n");
    if (result == 0) {
        printf("All tests PASSED\n");
    } else {
        printf("Some tests FAILED\n");
    }
    
    return result;
#else
    printf("ASCON support not compiled in WolfSSL\n");
    printf("To enable ASCON, configure WolfSSL with --enable-ascon or -DHAVE_ASCON\n");
    printf("==================\n");
    printf("Test SKIPPED\n");
    return 0;
#endif
}
