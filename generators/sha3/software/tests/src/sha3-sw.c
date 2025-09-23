#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "compiler.h"
#include <inttypes.h>
#include <math.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

int test_wolfssl_integration() {
    wc_Sha256 sha;
    unsigned char hash[WC_SHA256_DIGEST_SIZE];
    const char* message = "Hello RISC-V!";

    // Correct expected SHA256 hash for "Hello RISC-V!"
    unsigned char expected[] = {
        0xd1, 0xd0, 0x01, 0xff, 0x8f, 0xf0, 0x6f, 0xe6,
        0x5c, 0x96, 0x0a, 0xf4, 0xf3, 0x1c, 0x69, 0x71,
        0xd4, 0x6f, 0xfb, 0xc2, 0x19, 0x35, 0xd4, 0xfd,
        0xcc, 0x8e, 0x0b, 0x6a, 0xc0, 0x06, 0xa1, 0xc8
    };
    int ret = wc_InitSha256(&sha);
    ret = wc_Sha256Update(&sha, (const byte*)message, strlen(message));
    ret = wc_Sha256Final(&sha, hash);

    // Compare with expected result
    if (memcmp(hash, expected, WC_SHA256_DIGEST_SIZE) == 0) {
        printf("SHA256 test PASSED\n");
        printf("Input: \"%s\"\n", message);
        printf("Hash:  d1d001ff8ff06fe65c960af4f31c6971d46ffbc21935d4fdcc8e0b6ac006a1c8\n");
        return 0;
    } else {
        printf("SHA256 test FAILED\n");
        printf("Expected: d1d001ff8ff06fe65c960af4f31c6971d46ffbc21935d4fdcc8e0b6ac006a1c8\n");
        printf("Got:      ");
        for (int i = 0; i < WC_SHA256_DIGEST_SIZE; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
        return -1;
    }
}
int main(void) {
  unsigned long start, end;
  start = rdcycle();
  int result = test_wolfssl_integration();
  end = rdcycle();
  printf("SHA256 execution took %lu cycles\n", end - start);
  return 0;
}
