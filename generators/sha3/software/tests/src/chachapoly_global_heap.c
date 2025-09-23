#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "compiler.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/types.h>

#define HEAP_SIZE 65536
static unsigned char gHeap[HEAP_SIZE];
static WOLFSSL_HEAP_HINT* gHeapHint = NULL;

int initialize_wolfssl_memory() {
    memset(gHeap, 0, sizeof(gHeap));
    
    int ret = wc_LoadStaticMemory(&gHeapHint, gHeap, sizeof(gHeap), WOLFMEM_GENERAL, 10);
    if (ret != 0) {
        printf("Failed to initialize WolfSSL static memory: %d\n", ret);
        return ret;
    }
    
    // THIS IS THE KEY - Set global heap hint!
    void* oldHint = wolfSSL_SetGlobalHeapHint(gHeapHint);
    printf("WolfSSL static memory initialized (heap size: %d bytes)\n", HEAP_SIZE);
    printf("Set global heap hint: %p (was: %p)\n", gHeapHint, oldHint);
    
    return 0;
}

int test_chachapoly_with_global_heap() {
    printf("=== Testing ChaCha20-Poly1305 with Global Heap Hint ===\n");
    
    const char* plaintext = "Hello RISC-V Global Heap!";
    unsigned char key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    unsigned char nonce[CHACHA20_POLY1305_AEAD_IV_SIZE] = {0};
    unsigned char aad[] = "RISC-V AAD";
    unsigned char ciphertext[64];
    unsigned char tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    unsigned char decrypted[64];
    
    int plaintext_len = strlen(plaintext);
    int aad_len = strlen((char*)aad);
    
    printf("Plaintext: \"%s\" (%d bytes)\n", plaintext, plaintext_len);
    printf("AAD: \"%s\" (%d bytes)\n", aad, aad_len);
    printf("Global heap hint: %p\n", wolfSSL_GetGlobalHeapHint());
    
    // Now ChaCha20-Poly1305 should use our static memory via global hint
    printf("Calling wc_ChaCha20Poly1305_Encrypt...\n");
    
    int ret = wc_ChaCha20Poly1305_Encrypt(
        key, nonce,
        aad, aad_len,
        (const byte*)plaintext, plaintext_len,
        ciphertext, tag
    );
    
    printf("wc_ChaCha20Poly1305_Encrypt returned: %d\n", ret);
    
    if (ret != 0) {
        printf("ChaCha20-Poly1305 encryption failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        return -1;
    }
    
    printf("Encryption successful!\n");
    
    // Test decryption
    ret = wc_ChaCha20Poly1305_Decrypt(
        key, nonce,
        aad, aad_len,
        ciphertext, plaintext_len,
        tag, decrypted
    );
    
    if (ret != 0) {
        printf("ChaCha20-Poly1305 decryption failed: %d\n", ret);
        return -1;
    }
    
    decrypted[plaintext_len] = '\0';
    
    if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("Decryption successful: \"%s\"\n", decrypted);
        printf("ChaCha20-Poly1305 test PASSED!\n");
        
        printf("Ciphertext: ");
        for (int i = 0; i < plaintext_len; i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\n");
        
        printf("Tag: ");
        for (int i = 0; i < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE; i++) {
            printf("%02x", tag[i]);
        }
        printf("\n");
        
        return 0;
    } else {
        printf("ChaCha20-Poly1305 test FAILED - decryption mismatch\n");
        return -1;
    }
}

int main(void) {
    printf("WolfSSL ChaCha20-Poly1305 Global Heap Test\n");
    printf("==========================================\n");
    
    int init_ret = initialize_wolfssl_memory();
    if (init_ret != 0) {
        printf("Memory initialization failed\n");
        return init_ret;
    }
    
    unsigned long start = rdcycle();
    int result = test_chachapoly_with_global_heap();
    unsigned long end = rdcycle();
    
    printf("Test took %lu cycles\n", end - start);
    printf("==========================================\n");
    printf("Final result: %s\n", result == 0 ? "PASSED" : "FAILED");
    
    return result;
}