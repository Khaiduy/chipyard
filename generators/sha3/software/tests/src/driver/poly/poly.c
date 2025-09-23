/* See the file LICENSE for further information */

#include "driver/poly/poly.h"

void hwpoly1305_init(void* polyctrl, uint32_t key[8]){
  _REG32((char*)polyctrl, POLY_REG_RESET_N) = 0;
  _REG32((char*)polyctrl, POLY_REG_RESET_N) = 1;
  for(int i = 0; i < 8; i++) {
    _REG32((char*)polyctrl, POLY_REG_KEY_0+i*4) = key[i];   
  } 
  _REG32((char*)polyctrl, POLY_REG_INIT)    = 1;
  _REG32((char*)polyctrl, POLY_REG_INIT)    = 0;
  while(1){
    if(_REG32((char*)polyctrl, POLY_REG_READY) == 1){
      break;
    }
  }
}

void hwpoly1305_next(void* polyctrl, uint32_t block [4], int block_len){
  _REG32((char*)polyctrl, POLY_REG_BLOCK_LEN) = block_len; 
  for(int i = 0; i < 4; i++) {
    _REG32((char*)polyctrl, POLY_REG_BLOCK_0+i*4) = block[i];   
  } 
  _REG32((char*)polyctrl, POLY_REG_NEXT)  = 1;  
  _REG32((char*)polyctrl, POLY_REG_NEXT)  = 0;  
  while(1){
    if(_REG32((char*)polyctrl, POLY_REG_READY) == 1){
      break;
   }
  }
 }
 
 void hwpoly1305_finish(void* polyctrl){
  _REG32((char*)polyctrl, POLY_REG_FINISH) = 1;
  _REG32((char*)polyctrl, POLY_REG_FINISH) = 0; 
  while(1){
    if(_REG32((char*)polyctrl, POLY_REG_READY) == 1){
      break;
   }
  }
 }

void hwpoly1305_results(void* polyctrl){
    printf("%08x", _REG32((char*)polyctrl, POLY_REG_MAC_0));
    printf("%08x", _REG32((char*)polyctrl, POLY_REG_MAC_1));
    printf("%08x", _REG32((char*)polyctrl, POLY_REG_MAC_2));
    printf("%08x", _REG32((char*)polyctrl, POLY_REG_MAC_3));
    printf("\n");
}

void hwpoly1305_debug(void* polyctrl){
    for(int i = 0; i < 4; i++) {
        printf("%08x", _REG32((char*)polyctrl, POLY_REG_BLOCK_0+i*4));
    }
    printf("\n");
}



void hwpoly1305_selftest(void* polyctrl){
  uint32_t key_test [8]   = {0x85d6be78,0x57556d33,0x7f4452fe,0x42d506a8,0x0103808a,0xfb0db2fd,0x4abff6af,0x4149f51b};
  uint32_t block_test_1 [4]  ={0x43727970,0x746f6772,0x61706869,0x6320466f};
  uint32_t block_test_2 [4]  ={0x72756d20,0x52657365,0x61726368,0x2047726f};
  uint32_t block_test_3 [4]  ={0x75700000,0x00000000,0x00000000,0x00000000};
  
  hwpoly1305_init(polyctrl, key_test);
  hwpoly1305_next(polyctrl,block_test_1,16);
  hwpoly1305_next(polyctrl,block_test_2,16);
  hwpoly1305_next(polyctrl,block_test_3,2);
  hwpoly1305_finish(polyctrl);

  hwpoly1305_results(polyctrl); 
   printf("\n");
}

/* SOFTWARE */


static void poly_add(u32 a[5], const u32 b[5])
{
    u64 p[5] = {0};

    p[0] += (u64) a[0] + b[0];
    p[1] += (u64) a[1] + b[1];
    p[2] += (u64) a[2] + b[2];
    p[3] += (u64) a[3] + b[3];
    p[4] += (u64) a[4] + b[4];

    p[1] += (p[0] >> 32);
    p[2] += (p[1] >> 32);
    p[3] += (p[2] >> 32);
    p[4] += (p[3] >> 32);

    a[0] = (u32) p[0];
    a[1] = (u32) p[1];
    a[2] = (u32) p[2];
    a[3] = (u32) p[3];
    a[4] = (u32) p[4];
}

static void poly_mul(u32 a[5], const u32 b[4])
{
    u64 p[4] = {0};
    const u64 B[4] =
            {
                    5 * (b[0] >> 2), // !
                    5 * (b[1] >> 2),
                    5 * (b[2] >> 2),
                    5 * (b[3] >> 2),
            };

    /*
     *       a3     a2     a1     a0
     *  x    b3     b2     b1     b0
     *    --------------------------
     *    a3*b0  a2*b0  a1*b0  a0*b0
     *  + a2*b1  a1*b1  a0*b1
     *  + a1*b2  a0*b2
     *  + a0*b3
     *
     *  ...
     */
    p[0] = (u64) b[0] * a[0];
    p[1] = (u64) b[0] * a[1] + (u64) b[1] * a[0];
    p[2] = (u64) b[0] * a[2] + (u64) b[1] * a[1] + (u64) b[2] * a[0];
    p[3] = (u64) b[0] * a[3] + (u64) b[1] * a[2] + (u64) b[2] * a[1] + (u64) b[3] * a[0];

    /*
     *  ...
     *
     *  +                      a4*B0
     *  +               a4*B1  a3*B1
     *  +        a4*B2  a3*B2  a2*B2
     *  + a4*B3  a3*B3  a2*B3  a1*B3
     */
    p[0] += (B[0] * a[4] + B[1] * a[3] + B[2] * a[2] + B[3] * a[1]);
    p[1] += (B[1] * a[4] + B[2] * a[3] + B[3] * a[2]);
    p[2] += (B[2] * a[4] + B[3] * a[3]);
    p[3] += (B[3] * a[4]);

    // carry & recover bits
    const u64 bits = a[4] * (b[0] & 0b00000011) + (p[3] >> 32);
    u64 carry = 5 * (bits >> 2);

    carry += (u32) p[0];
    a[0] = (u32) carry;
    carry >>= 32;

    carry += (u32) p[1] + (p[0] >> 32);
    a[1] = (u32) carry;
    carry >>= 32;

    carry += (u32) p[2] + (p[1] >> 32);
    a[2] = (u32) carry;
    carry >>= 32;

    carry += (u32) p[3] + (p[2] >> 32);
    a[3] = (u32) carry;
    carry >>= 32;

    carry += (bits & 0b00000011);
    a[4] = (u32) carry;
}

/*
 *  poly1305 process full blocks
 */
static void poly_block(const u32 r[4],
                              const u8 input[16],
                              u32 accum[5])
{
    u32 block[5] = {0};

    block[0] = u8_u32le((input));
    block[1] = u8_u32le((input + 4));
    block[2] = u8_u32le((input + 8));
    block[3] = u8_u32le((input + 12));

    // add 2^128 to block
    block[4] = 1;

    poly_add(accum, block);
    poly_mul(accum, r);
}

/*
 *  zero pad and poly remaining bytes
 */
static inline void poly_tail(uint32_t accum[5],const uint32_t r[4],const uint8_t *buf,const uint32_t remaining)
{
    // x5 u32
    u8 bytes[20] = {0};

    for (u32 i = 0; i < remaining; i++)
    {
        bytes[i] = buf[i];
    }

    // one bit beyond the number of octets
    bytes[remaining] = 1;

    poly_add(accum, (u32 *) bytes);
    poly_mul(accum, r);
}

/*
 *  complete poly & output tag
 */
void poly_final(uint32_t accum[5],uint32_t s[5], uint8_t *output)
{
  uint64_t final[4] = {0};

  uint64_t carry = (uint64_t) 5 + accum[0];
  carry >>= 32;

  carry += accum[1];
  carry >>= 32;

  carry += accum[2];
  carry >>= 32;

  carry += accum[3];
  carry >>= 32;

  carry += accum[4];
  carry = 5 * (carry >> 2);

  poly_add(accum, s);

  // if carry > 0 here, this is equivalent to
  // subtracting 0x3fffffffffffffffffffffffffffffffb
  final[0] = carry + accum[0];
  final[1] = (final[0] >> 32) + accum[1];
  final[2] = (final[1] >> 32) + accum[2];
  final[3] = (final[2] >> 32) + accum[3];

  // return num_to_16_le_bytes(a)
  

  u32_u8le(((uint32_t) final[0]), output);
  u32_u8le(((uint32_t) final[1]), (output + 4));
  u32_u8le(((uint32_t) final[2]), (output + 8));
  u32_u8le(((uint32_t) final[3]), (output + 12));
   
}

void poly1305_state(uint32_t r[4], uint32_t s[4], const uint8_t key[32])
{
  r[0] = u8_u32le((key));
  r[1] = u8_u32le((key + 4));
  r[2] = u8_u32le((key + 8));
  r[3] = u8_u32le((key + 12));

  // 'clamp' r
  r[0] &= 0x0fffffff;
  r[1] &= 0x0ffffffc;
  r[2] &= 0x0ffffffc;
  r[3] &= 0x0ffffffc;
  s[0] = u8_u32le((key + 16));
  s[1] = u8_u32le((key + 20));
  s[2] = u8_u32le((key + 24));
  s[3] = u8_u32le((key + 28));
}

/*
 *  main poly1305 operation
 *
 *  process a number of available blocks,
 *  process remaining bytes, output tag
 */
void poly1305_tag(const uint8_t key[32], const uint8_t *buf, const uint32_t len, uint8_t *out){
    
  uint32_t r[4] = {0};
  uint32_t s[5] = {0};
  uint32_t accum[5] = {0};
  // poly1305_state(r, s, key);

  r[0] = u8_u32le((key));
  r[1] = u8_u32le((key + 4));
  r[2] = u8_u32le((key + 8));
  r[3] = u8_u32le((key + 12));

  // 'clamp' r
  r[0] &= 0x0fffffff;
  r[1] &= 0x0ffffffc;
  r[2] &= 0x0ffffffc;
  r[3] &= 0x0ffffffc;
  s[0] = u8_u32le((key + 16));
  s[1] = u8_u32le((key + 20));
  s[2] = u8_u32le((key + 24));
  s[3] = u8_u32le((key + 28));


  uint32_t len_aligned = align16(len);
  uint32_t remaining = len - len_aligned;
  for (uint32_t i = 0; i < len_aligned; i += 16){
      poly_block(r, buf + i, accum);
  }
  if (remaining){
      buf += len_aligned;
      poly_tail(accum, r, buf, remaining);
  }   

  // poly_final(accum, s, out);

  uint64_t final[4] = {0};

  uint64_t carry = (uint64_t) 5 + accum[0];
  carry >>= 32;

  carry += accum[1];
  carry >>= 32;

  carry += accum[2];
  carry >>= 32;

  carry += accum[3];
  carry >>= 32;

  carry += accum[4];
  carry = 5 * (carry >> 2);

  poly_add(accum, s);

  // if carry > 0 here, this is equivalent to
  // subtracting 0x3fffffffffffffffffffffffffffffffb
  final[0] = carry + accum[0];
  final[1] = (final[0] >> 32) + accum[1];
  final[2] = (final[1] >> 32) + accum[2];
  final[3] = (final[2] >> 32) + accum[3];

  // return num_to_16_le_bytes(a)
  
  u32_u8le(((uint32_t) final[0]), out);
  u32_u8le(((uint32_t) final[1]), (out + 4));
  u32_u8le(((uint32_t) final[2]), (out + 8));
  u32_u8le(((uint32_t) final[3]), (out + 12));
    
}

