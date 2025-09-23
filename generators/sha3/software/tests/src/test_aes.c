#include <stdio.h>
#include <string.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 12
#define AES_TAG_SIZE 16

int main(void) {
    int ret;
    Aes aes;
    // 256-bit key (from test_aes.c)
    byte key[AES_KEY_SIZE] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    // 12-byte IV (GCM standard)
    byte iv[AES_IV_SIZE] = {0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x11,0x22,0x33,0x44};
    // Example plaintext
    byte pt[] = "Now is the time for all good men";
    byte aad[] = "aad";
    byte ct[64] = {0};
    byte tag[AES_TAG_SIZE] = {0};
    byte dec[64] = {0};

    printf("Testing AES-GCM (style: test_aes.c)\n");

    // Init
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    printf("wc_AesInit: %d\n", ret);

    // Set Key
    ret = wc_AesGcmSetKey(&aes, key, AES_KEY_SIZE);
    printf("wc_AesGcmSetKey: %d\n", ret);

    // Encrypt
    ret = wc_AesGcmEncrypt(&aes, ct, pt, strlen((char*)pt), iv, AES_IV_SIZE, tag, AES_TAG_SIZE, aad, strlen((char*)aad));
    printf("wc_AesGcmEncrypt: %d\n", ret);

    // Decrypt
    ret = wc_AesGcmDecrypt(&aes, dec, ct, strlen((char*)pt), iv, AES_IV_SIZE, tag, AES_TAG_SIZE, aad, strlen((char*)aad));
    printf("wc_AesGcmDecrypt: %d\n", ret);

    // Check result
    if (memcmp(pt, dec, strlen((char*)pt)) == 0) {
        printf("AES-GCM roundtrip: PASS\n");
    } else {
        printf("AES-GCM roundtrip: FAIL\n");
    }

    wc_AesFree(&aes);
    return 0;
}