#include <stdio.h>
#include <stdint.h>
//#include <string.h>
#include "encoding.h"
#include "compiler.h"
#include <inttypes.h>
#include <math.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/types.h>

int test_chacha20_poly1305() {
    printf("=== Testing ChaCha20-Poly1305 ===\n");
    
    // Test vectors (simplified)
    const char* plaintext = "Hello RISC-V!";
    unsigned char key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    unsigned char nonce[CHACHA20_POLY1305_AEAD_IV_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    
    unsigned char aad[] = "RISC-V";
    unsigned char ciphertext[64];
    unsigned char tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    unsigned char decrypted[64];
    
    int plaintext_len = strlen(plaintext);
    int aad_len = strlen((char*)aad);
    
    // Encryption
    int ret = wc_ChaCha20Poly1305_Encrypt(
        key, nonce,
        aad, aad_len,
        (const byte*)plaintext, plaintext_len,
        ciphertext, tag
    );
    
    if (ret != 0) {
        printf("ChaCha20-Poly1305 encryption failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        return -1;
    }
    
    printf("Encryption successful!\n");
    printf("Plaintext:  \"%s\"\n", plaintext);
    printf("Key:        ");
    for (int i = 0; i < CHACHA20_POLY1305_AEAD_KEYSIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    
    printf("Nonce:      ");
    for (int i = 0; i < CHACHA20_POLY1305_AEAD_IV_SIZE; i++) {
        printf("%02x", nonce[i]);
    }
    printf("\n");
    
    printf("Ciphertext: ");
    for (int i = 0; i < plaintext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    
    printf("Tag:        ");
    for (int i = 0; i < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");
    
    // Decryption
    ret = wc_ChaCha20Poly1305_Decrypt(
        key, nonce,
        aad, aad_len,
        ciphertext, plaintext_len,
        tag, decrypted
    );
    
    if (ret != 0) {
        printf("ChaCha20-Poly1305 decryption failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        return -1;
    }
    
    // Null terminate decrypted text for printing
    decrypted[plaintext_len] = '\0';
    
    // Verify decryption
    if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("Decrypted:  \"%s\"\n", decrypted);
        printf("ChaCha20-Poly1305 test PASSED\n");
        return 0;
    } else {
        printf("ChaCha20-Poly1305 test FAILED - decryption mismatch\n");
        printf("Expected: \"%s\"\n", plaintext);
        printf("Got:      \"%s\"\n", decrypted);
        return -1;
    }
}

int main(void) {
    printf("WolfSSL ChaCha20-Poly1305 Test\n");
    printf("==============================\n");

    unsigned long start, end;
    
    start = rdcycle();
    int result = test_chacha20_poly1305();
    end = rdcycle();
    
    printf("ChaCha20-Poly1305 execution took %lu cycles\n", end - start);
    
    printf("==============================\n");
    if (result == 0) {
        printf("Test PASSED\n");
    } else {
        printf("Test FAILED\n");
    }
    
    return result;
}
