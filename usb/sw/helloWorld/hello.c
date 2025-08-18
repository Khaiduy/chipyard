// #include <stdio.h>
#include <stdint.h>
#include <riscv-pk/encoding.h>
#include "include/platform.h"
#include "kprintf.h"
#include "driver/trng/trng.h"
#include "driver/chacha/chacha.h"
#include "driver/uart/uart.h"
#include "driver/poly/poly.h"
#include "driver/ecdsa_block.c"
#include "driver/ecdsa/ecdsa.h"
#include "driver/aes/aes.h"

#define REG32(p, i)	((p)[(i) >> 2])

// #define TRNG_TEST
// #define CHACHA_TEST
// #define POLY_TEST
// #define ECDSA_TEST
// #define SHA3_TEST
#define AES_TEST

int main(int argc, char **arv) {
  
  REG32(uart, UART_REG_TXCTRL) = UART_TXEN;

  uint32_t mhartid = read_csr(mhartid);

  kprintf("Hello world from core %c!!!\r\n", mhartid + 48);

  #ifdef TRNG_TEST
  kprintf("TRNG testing software\n");
  int status = 0;
  uint32_t rand = 0;
  uint32_t numbers = 10;
  kprintf("Setup TRNG...\n");
  uintptr_t trng_reg= 0x64005000;
  status = trng_setup((void*)trng_reg, (0x1 << 5));

  // kprintf("DONE\n");
  if((status == TRNG_ERROR_WAIT) || (status == TRNG_ERROR_RANDOM)){
    kprintf("Error setup trng\n");
  }else{
    for(int i = 0; i < numbers; i++){
      rand = trng_get_random((void*)trng_reg);
      if(rand == TRNG_ERROR_RANDOM){
        kprintf("Errot gen random\n");
        break;
      }
      kprintf("%x\n",rand);
    }
  }
  trng_reset_disable((void*)trng_reg);
  #endif //TRNG_TEST

  #ifdef CHACHA_TEST

  kprintf("CHACHA testing software\n");
  uintptr_t chachactrl= 0x64006000;
  kprintf("Begin CHACHA20 hardware test:\r\n\n\n");
  // Software encrypt CHACHA20
  kprintf("\rSoftware: \n\n");
  //-------------
  uint8_t key[] = {0x00, 0x01, 0x02, 0x03,0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0a, 0x0b,0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13,0x14, 0x15, 0x16, 0x17,0x18, 0x19, 0x1a, 0x1b,0x1c, 0x1d, 0x1e, 0x1f};
  uint8_t nonce[] = {0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
  uint8_t plain_text[] ={0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
                          0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
                          0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
                          0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
                          0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
                          0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
                          0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
                          0x74,0x2e};
  uint32_t counter = 1;
  uint8_t plain_text_out[128];
  ChaCha20XOR(key,counter,nonce,plain_text,plain_text_out,128);
  int count=0;
  for(int i = 0; i < 128; i++){
    if (count ==16){
      kprintf("\n");
      count = 1;    
    }
    else { count=count+1;}
      uart_put_hex_1b((void*)uart, plain_text_out[i]);
    }
  kprintf("\n");
  kprintf("\n");
  //-------------
  // Hardware CHACHA20
  kprintf("\rHardware: \n\n");
  hwchacha20_selftest((void*)chachactrl);                 
  //-------------  
  #endif //CHACHA_TEST

  #ifdef POLY_TEST
  kprintf("POLY testing software\n");
  uintptr_t poly_reg= 0x64007000;

  // Keys Test Software
  const uint8_t   key[32] = {0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
                    0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
                    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
                    0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};
  const uint8_t   block[] = {0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
                        0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f,
                        0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65,
                        0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f,
                        0x75, 0x70};
  const uint32_t  block_len = 34;
  uint8_t   mac[16];

  // Setup software

  uart_puts((void*)uart,"Begin POLY1305 hardware test:\r\n");
  uart_puts((void*)uart,"\n\n");

  // Software Poly1305
  uart_puts((void*)uart, "Software: ");

  poly1305_tag(key,block,block_len,mac);
  
  //Print result Software 
  int count=0;
  for(int i = 0; i < 16; i++){
    if (count ==16){
      uart_puts((void*)uart,"\n");
      count = 1;    
    }
    else { count=count+1;}
    uart_put_hex_1b((void*)uart, mac[i]);
    }
  uart_puts((void*)uart,"\n\n");
  
  // Hardware Poly1305
  // -------------
  
  uart_puts((void*)uart, "Hardware \n");
  hwpoly1305_selftest((void*)poly_reg);
  #endif //POLY_TEST

  #ifdef ECDSA_TEST
  uart_puts((void*)uart,"Begin ECDSA hardware test:\r\n");
  uart_puts((void*)uart,"\n");
  // Software 
  uart_puts((void*)uart, "Software: \n");
  // uint64_t start_mtime;
  // uint64_t delta_mtime;
  // start_mtime = clkutils_read_mtime();
//-------------

  uint8_t p_publicKey[ECC_BYTES+1]; 
  uint8_t p_privateKey[ECC_BYTES]; 
  //a ramdom number
  /*
  Msg = 5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8
  d = 519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464
  Qx = 1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83
  Qy = ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9
  k = 94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de
  R = f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac
  S = 8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903

  Msg = c35e2f092553c55772926bdbe87c9796827d17024dbb9233a545366e2e5987dd344deb72df987144b8c6c43bc41b654b94cc856e16b96d7a821c8ec039b503e3d86728c494a967d83011a0e090b5d54cd47f4e366c0912bc808fbb2ea96efac88fb3ebec9342738e225f7c7c2b011ce375b56621a20642b4d36e060db4524af1
  d =   0f56db78ca460b05 5c500064824bed99 9a25aaf48ebb519a c201537b85479813
  Qx =  e266ddfdc12668db 30d4ca3e8f774943 2c416044f2d2b8c1 0bf3d4012aeffa8a
  Qy =  bfa86404a2e9ffe6 7d47c587ef7a97a7 f456b863b4d02cfc 6928973ab5b1cb39
  k =   6d3e71882c3b83b1 56bb14e0ab184aa9 fb728068d3ae9fac 421187ae0b2f34c6
  R =   976d3a4e9d23326d c0baa9fa560b7c4e 53f42864f508483a 6473b6a11079b2db
  S =   1b766e9ceb71ba6c 01dcd46e0af462cd 4cfa652ae5017d45 55b8eeefe36e1932
  */
  //uint64_t d[4]={0xca54a56dda72b464,0x5b44c8130b4e3eac,0x1f4fa8ee59f4771a,0x519b423d715f8b58};
  uint64_t d[4]={0xc201537b85479813,0x9a25aaf48ebb519a,0x5c500064824bed99,0x0f56db78ca460b05};
  // start_mtime = clkutils_read_mtime();
  if(!ecc_make_key(secp256r1,p_publicKey,p_privateKey,   d)){
      kprintf("Error key gen");
  }
  // delta_mtime = clkutils_read_mtime() - start_mtime;

  kprintf("Public key: \n");
  kprintf("X: \n");
  int count = 0;
  for (int i=0; i<4;i++){
       for (int j=1; j<8+1;j++){
       count++;
       uart_put_hex_1b((void*)uart, p_publicKey[j+8*i]);
       if(count == 16){
          uart_puts((void*)uart, "\n");
          count = 0;
        }
       }
  }
  // uart_puts((void*)uart,"\n");
  // uart_puts((void*)uart, "\r\nTime generate key: ");
  // print_meas(delta_mtime);
  uart_puts((void*)uart, "\n");
  //uint64_t sha256hash[NUM_ECC_DIGITS]={0xdbc4e7a6a133ec56,0x4e1e2efb1a900377,0xc2c5897204fe0950,0x44acf6b7e36c1342};
  uint64_t sha256hash[ECC_BYTES]={ 0x12b134f489ab2bbc,0x114e0b9ff4080bea,0xc7608b4d6cc1dec0,0x9b2db89cb0e8fa3c};
  uint8_t p_hash[ECC_BYTES];
  ecc_native2bytes(secp256r1,p_hash, sha256hash);
  uint8_t p_signature[ECC_BYTES*2];
  //uint64_t k[NUM_ECC_DIGITS]={0xb9670787642a68de,0x3b4a6247824f5d33,0xa280f245f9e93c7f,0x94a1bbb14b906a61};
  uint64_t k[NUM_ECC_DIGITS]=  {0x421187ae0b2f34c6,0xfb728068d3ae9fac,0x56bb14e0ab184aa9,0x6d3e71882c3b83b1};
  // start_mtime = clkutils_read_mtime();
  if(!ecdsa_sign(secp256r1,p_privateKey, p_hash,p_signature, k))
  {
      kprintf("Error sign");
  }
  // delta_mtime = clkutils_read_mtime() - start_mtime;
  kprintf("\n");
  kprintf("Signature: \n");
  kprintf("R: \n");
  count = 0;
  for (int i=0; i<4;i++){
       for (int j=0; j<8;j++){
         count++;
         uart_put_hex_1b((void*)uart, p_signature[j+8*i]);
         if(count == 16){
           uart_puts((void*)uart, "\n");
           count = 0;
        }
       }
  }
  kprintf("\n");
  count = 0;
  //TODO: S print a unexpected value, need debug
  
  kprintf("S: \n");
  for (int i=4; i<8;i++){
       for (int j=0; j<8;j++){
         count++;
         uart_put_hex_1b((void*)uart, p_signature[j+(8*i)]);
         if(count == 16){
           uart_puts((void*)uart, "\n");
           count = 0;
        }
       }
  }
  
  // uart_puts((void*)uart,"\n");
  // uart_puts((void*)uart, "\r\nTime sign: ");
  // print_meas(delta_mtime);
  uart_puts((void*)uart, "\n");
  // start_mtime = clkutils_read_mtime();
  if(!ecdsa_verify(secp256r1,p_publicKey, p_hash, p_signature))
  {
    // delta_mtime = clkutils_read_mtime() - start_mtime;
    kprintf("Error verify");
  } else {
    // delta_mtime = clkutils_read_mtime() - start_mtime;
    kprintf("ECDSA secp256r1 finish\n");
  }


  uintptr_t ecdsa_reg= 0x64008000;
  kprintf("----------------------------------\n");
  uart_puts((void*)uart, "\rHardware: \n\n");
  //-------------
  hw_ecdsa_primitives_selftest((void*)ecdsa_reg);                 
  //-------------  
  #endif //ECDSA_TEST

  #ifdef AES_TEST
  kprintf("AES testing software\n");
  uintptr_t aes_reg= 0x64009000;
  kprintf("Begin AES hardware test:\r\n\n\n");

  // Hardware encrypt AES
  kprintf("Hardware: \n\n");
  //-------------
  hwaes_selftest((void*)aes_reg);
  #endif //AES_TEST

  return 0;
}
