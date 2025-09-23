/* See the file LICENSE for further information */

#include "driver/chacha/chacha.h"
#include "mmio.h"

void hwchacha_init(void* chachactrl){
  _REG32((char*)chachactrl, CHACHA_REG_RST_CORE) =  0x0;
  _REG32((char*)chachactrl, CHACHA_REG_RST_CORE) =  0x1;
  _REG32((char*)chachactrl, CHACHA_REG_INIT) = 1;
  _REG32((char*)chachactrl, CHACHA_REG_INIT) = 0;
  while(1){
    if(_REG32((char*)chachactrl, CHACHA_REG_READY) == 1){
      break;
    }
  }
}

void hwchacha_next(void* chachactrl){
  _REG32((char*)chachactrl, CHACHA_REG_NEXT) = 1;
  _REG32((char*)chachactrl, CHACHA_REG_NEXT) = 0;
  while(1){
    if(_REG32((char*)chachactrl, CHACHA_REG_READY) == 1){
      break;
    }
  }
}


void hwchacha20_init(void* chachactrl, uint32_t key[8], uint32_t nonce[3],uint32_t counter, uint32_t plain_text [16]){
  for(int i = 0; i < 8; i++) {
    _REG32((char*)chachactrl, CHACHA_REG_KEY_0+i*4) = key[i];
  }
  for(int ii = 0; ii < 3; ii++) {
    _REG32((char*)chachactrl, CHACHA_REG_NONCE_0+ii*4) = nonce[ii];   
  }
  _REG32((char*)chachactrl, CHACHA_REG_B_COUNTER) = counter;
  for(int jj = 0; jj < 16; jj++) {
    _REG32((char*)chachactrl, CHACHA_REG_IN_0+jj*4) = plain_text[jj];   
  }
  hwchacha_init(chachactrl);  
}


void hwchacha20_next(void* chachactrl, uint32_t plain_text [16]){
  for(int jj = 0; jj < 16; jj++) {
    _REG32((char*)chachactrl, CHACHA_REG_IN_0+jj*4) = plain_text[jj];   
  }     
  hwchacha_next(chachactrl);
 }


void hwchacha20_results(void* chachactrl){
    printf("Results:\n");
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_0));
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_1));
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_2));
    printf("%x\n",_REG32((char*)chachactrl, CHACHA_REG_OUT_3));
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_4));
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_5));
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_6));
    printf("%x\n",_REG32((char*)chachactrl, CHACHA_REG_OUT_7));
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_8));
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_9));
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_10));
    printf("%x\n",_REG32((char*)chachactrl, CHACHA_REG_OUT_11));
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_12));
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_13));
    printf("%x",_REG32((char*)chachactrl, CHACHA_REG_OUT_14));
    printf("%x\n",_REG32((char*)chachactrl, CHACHA_REG_OUT_15));
}

void hwchacha20_selftest(void* chachactrl){
    uint32_t key_test [8]   = {0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f,0x10111213,0x14151617,0x18191a1b,0x1c1d1e1f};
    uint32_t nonce_test [3] = {0x00000000,0x0000004a,0x00000000};
    uint32_t counter_test   = 1;
    uint32_t plain_test [16]  ={0x4c616469,0x65732061,0x6e642047,0x656e746c,
                                0x656d656e,0x206f6620,0x74686520,0x636c6173,
                                0x73206f66,0x20273939,0x3a204966,0x20492063,
                                0x6f756c64,0x206f6666,0x65722079,0x6f75206f};     
    uint32_t plain_test_2 [16]={0x6e6c7920,0x6f6e6520,0x74697020,0x666f7220,
                                0x74686520,0x66757475,0x72652c20,0x73756e73,
                                0x63726565,0x6e20776f,0x756c6420,0x62652069,
                                0x742e0000,0x00000000,0x00000000,0x00000000};
    hwchacha20_init(chachactrl, key_test, nonce_test, counter_test, plain_test);

    hwchacha20_results(chachactrl);

    hwchacha20_next(chachactrl,plain_test_2);

    hwchacha20_results(chachactrl); 
    printf("\n");
}






/* SOFTWARE */
static inline void u32t8le(uint32_t v, uint8_t p[4]) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static inline uint32_t u8t32le(uint8_t p[4]) {
    uint32_t value = p[3];

    value = (value << 8) | p[2];
    value = (value << 8) | p[1];
    value = (value << 8) | p[0];

    return value;
}

static inline uint32_t rotl32(uint32_t x, int n) {
    // http://blog.regehr.org/archives/1063
    return x << n | (x >> (-n & 31));
}

// https://tools.ietf.org/html/rfc7539#section-2.1
static void chacha20_quarterround(uint32_t *x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a],  8);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c],  7);
}

static void chacha20_serialize(uint32_t in[16], uint8_t output[64]) {
    int i;
    for (i = 0; i < 16; i++) {
        u32t8le(in[i], output + (i << 2));
    }
}

void chacha20_block(uint32_t in[16], uint8_t out[64], int num_rounds) {
    int i;
    uint32_t x[16];

    memcpy(x, in, sizeof(uint32_t) * 16);

    for (i = num_rounds; i > 0; i -= 2) {
        chacha20_quarterround(x, 0, 4,  8, 12);
        chacha20_quarterround(x, 1, 5,  9, 13);
        chacha20_quarterround(x, 2, 6, 10, 14);
        chacha20_quarterround(x, 3, 7, 11, 15);
        chacha20_quarterround(x, 0, 5, 10, 15);
        chacha20_quarterround(x, 1, 6, 11, 12);
        chacha20_quarterround(x, 2, 7,  8, 13);
        chacha20_quarterround(x, 3, 4,  9, 14);
    }

    for (i = 0; i < 16; i++) {
        x[i] += in[i];
    }

    chacha20_serialize(x, out);
}

// https://tools.ietf.org/html/rfc7539#section-2.3
static void chacha20_init_state(uint32_t s[16], uint8_t key[32], uint32_t counter, uint8_t nonce[12]) {
    int i;

    // refer: https://dxr.mozilla.org/mozilla-beta/source/security/nss/lib/freebl/chacha20.c
    // convert magic number to string: "expand 32-byte k"
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    for (i = 0; i < 8; i++) {
        s[4 + i] = u8t32le(key + i * 4);
    }

    s[12] = counter;

    for (i = 0; i < 3; i++) {
        s[13 + i] = u8t32le(nonce + i * 4);
    }
}

void ChaCha20XOR(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *in, uint8_t *out, int inlen) {
    int i, j;

    uint32_t s[16];
    uint8_t block[64];

    chacha20_init_state(s, key, counter, nonce);

    for (i = 0; i < inlen; i += 64) {
        chacha20_block(s, block, 20);
        s[12]++;

        for (j = i; j < i + 64; j++) {
            if (j >= inlen) {
                break;
            }
            out[j] = in[j] ^ block[j - i];
        }
    }
}




