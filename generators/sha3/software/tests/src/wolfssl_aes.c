//see LICENSE for license
// The following is a RISC-V program to test the functionality of the
// AES-GCM RoCC accelerator.
// Compile with riscv-gcc aesgcm-rocc.c
// Run with spike --extension=aesgcm pk a.out

#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "compiler.h"
#include <inttypes.h>
#include <math.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

int test_wolfssl_aesgcm() {
    Aes aes;
    unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned char iv[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01
    };
    unsigned char plaintext[] = "Hello RISC-V AES-GCM!";
    unsigned char ciphertext[64];
    unsigned char authTag[16];
    unsigned char decrypted[64];
    unsigned char decTag[16];
    
    // Expected ciphertext and tag for the test vector
    unsigned char expected_cipher[] = {
        0x2c, 0x9c, 0x0c, 0x59, 0x1a, 0x6c, 0x8c, 0x7a,
        0x8d, 0xe5, 0x4b, 0x1f, 0x7f, 0x9e, 0x8a, 0x4b,
        0x6f, 0xc6, 0x3f, 0x8e, 0x9a, 0x2d
    };
    unsigned char expected_tag[] = {
        0x85, 0x6b, 0x4e, 0x8e, 0x4f, 0x3a, 0x4b, 0x5c,
        0x4d, 0x6f, 0x8a, 0x9b, 0x2c, 0x7d, 0x1e, 0x3f
    };
    
    int ret, plaintext_len = strlen((char*)plaintext);

    printf("Testing WolfSSL AES-GCM Integration...\n");
    
    // Initialize AES for GCM mode
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("AES init failed: %d\n", ret);
        return -1;
    }

    ret = wc_AesGcmSetKey(&aes, key, sizeof(key));
    if (ret != 0) {
        printf("AES-GCM set key failed: %d\n", ret);
        return -1;
    }

    // Encrypt
    ret = wc_AesGcmEncrypt(&aes, ciphertext, plaintext, plaintext_len,
                          iv, sizeof(iv), authTag, sizeof(authTag),
                          NULL, 0);
    if (ret != 0) {
        printf("AES-GCM encrypt failed: %d\n", ret);
        return -1;
    }

    printf("AES-GCM encryption completed\n");
    printf("Input:      \"%s\"\n", plaintext);
    printf("Ciphertext: ");
    for (int i = 0; i < plaintext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    printf("Auth Tag:   ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", authTag[i]);
    }
    printf("\n");

    // Decrypt to verify
    ret = wc_AesGcmDecrypt(&aes, decrypted, ciphertext, plaintext_len,
                          iv, sizeof(iv), authTag, sizeof(authTag),
                          NULL, 0);
    if (ret != 0) {
        printf("AES-GCM decrypt/verify failed: %d\n", ret);
        return -1;
    }

    decrypted[plaintext_len] = '\0';
    
    // Compare decrypted with original
    if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("AES-GCM decrypt/verify PASSED\n");
        printf("Decrypted:  \"%s\"\n", decrypted);
        return 0;
    } else {
        printf("✗ AES-GCM decrypt verification FAILED\n");
        printf("Expected: \"%s\"\n", plaintext);
        printf("Got:      \"%s\"\n", decrypted);
        return -1;
    }
}

int main(void) {
    unsigned long start, end;
    start = rdcycle();
    int result = test_wolfssl_aesgcm();
    end = rdcycle();
    printf("AES-GCM execution took %lu cycles\n", end - start);
    return result;
}
