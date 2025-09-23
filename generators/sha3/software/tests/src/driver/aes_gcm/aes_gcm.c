/* See the file LICENSE for further information */

#include "driver/aes_gcm/aes_gcm.h"
#include "mmio.h"
#include "encoding.h"
#include <stdlib.h>   // add near top of file with other includes

#define AES_SMALL 1

#define AES_GCM 0
#define AES_ONLY 1
#define ENC_MODE 1
#define DEC_MODE 0
#define HASHKEY_YES 1
#define HASHKEY_NO 0
#define AES_128_BIT_KEY 0
#define AES_256_BIT_KEY 1
#define WD 100000

void hw_aes_gcm_reset (void* aes_gcmctrl){
  //set reset
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IRESETN) = 0;
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_ICTRL) = 0;
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IRESETN) = 1;
}

void hw_aes_gcm_set_key (void* aes_gcmctrl,uint64_t * key, uint64_t keylen){
 _REG64((char*)aes_gcmctrl, AES_GCM_REG_IKEY_0) = key[0];
 _REG64((char*)aes_gcmctrl, AES_GCM_REG_IKEY_1) = key[1];
 _REG64((char*)aes_gcmctrl, AES_GCM_REG_IKEY_2) = key[2];
 _REG64((char*)aes_gcmctrl, AES_GCM_REG_IKEY_3) = key[3];
 _REG64((char*)aes_gcmctrl, AES_GCM_REG_IKEYLEN) = keylen;
 _REG64((char*)aes_gcmctrl, AES_GCM_REG_IKEY_VALID) = 1;
}

void hw_aes_gcm_clear_key (void* aes_gcmctrl){
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IKEY_VALID) = 0;
}

void hw_aes_gcm_set_aad (void* aes_gcmctrl,uint64_t * aad){
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IAAD_0) = aad[0];
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IAAD_1) = aad[1];
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IAAD_VALID) = 1;
}

void hw_aes_gcm_clear_aad (void* aes_gcmctrl){
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IAAD_VALID) = 0;
}

void hw_aes_gcm_set_iiv (void* aes_gcmctrl, uint64_t * iv ){
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IIV_0) = iv[0];
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IIV_1) = iv[1];
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IIV_VALID) = 1;
}

void hw_aes_gcm_clear_iiv (void* aes_gcmctrl){
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IIV_VALID) = 0;
}

void hw_aes_gcm_set_block (void* aes_gcmctrl,uint64_t * block, size_t valid_bytes){
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IBLOCK_0) = block[0];
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IBLOCK_1) = block[1];
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IBLOCK_BYTES) = (valid_bytes == 16) ? 0 : valid_bytes;
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IBLOCK_VALID) = 1;
}

void hw_aes_gcm_clear_block (void* aes_gcmctrl){
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_IBLOCK_VALID) = 0;
}

void hw_aes_gcm_set_tag (void* aes_gcmctrl,uint64_t * tag ){
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_ITAG_0) = tag[0];
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_ITAG_1) = tag[1];
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_ITAG_VALID) = 1;
}

void hw_aes_gcm_clear_tag (void* aes_gcmctrl){
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_ITAG_VALID) = 0;
}

void hw_aes_gcm_ctrl (void* aes_gcmctrl, uint32_t init, uint32_t next, uint32_t encdec, uint32_t aad_only){
  _REG64((char*)aes_gcmctrl, AES_GCM_REG_ICTRL) = (init<<3)| (next<<2) | (encdec<<1) | (aad_only);
}

int hw_aes_gcm_read_tag(void* aes_gcmctrl, uint64_t * tag){
  uint32_t wd = 0;
  uint64_t v;
  /* Wait until tag valid == 1 */
  do {
    v = _REG64((char*)aes_gcmctrl, AES_GCM_REG_OTAG_VALID);
    if (++wd > WD) {
      printf("ERROR: read tag failed (timeout)\n");
      return -1;
    }
  } while (v != 1);

  tag[0] = _REG64((char*)aes_gcmctrl, AES_GCM_REG_OTAG_0);
  tag[1] = _REG64((char*)aes_gcmctrl, AES_GCM_REG_OTAG_1);
  return 0;
}

int hw_aes_gcm_read_result(void* aes_gcmctrl, uint64_t * result){
  uint32_t wd = 0;
  uint64_t v;
  /* Wait until result valid == 1 */
  do {
    v = _REG64((char*)aes_gcmctrl, AES_GCM_REG_ORESULT_VALID);
    if (++wd > WD) {
      printf("ERROR: read result failed (timeout)\n");
      return -1;
    }
  } while (v != 1);

  result[0] = _REG64((char*)aes_gcmctrl, AES_GCM_REG_ORESULT_0);
  result[1] = _REG64((char*)aes_gcmctrl, AES_GCM_REG_ORESULT_1);
  return 0;
}

int hw_aes_gcm_authentic (void* aes_gcmctrl){
  if(_REG64((char*)aes_gcmctrl, AES_GCM_REG_OAUTHENTIC)== 1)
    return 1;
  else
    return 0;
}

int hw_aes_gcm_ready (void* aes_gcmctrl){
  if(_REG64((char*)aes_gcmctrl, AES_GCM_REG_OREADY)== 1)
    return 1;
  else
    return 0;
}

int hw_aes_gcm_wait_ready (void* aes_gcmctrl){
uint32_t wd = 0;
  while(1){
    if (_REG64((char*)aes_gcmctrl, AES_GCM_REG_OREADY) == 1){
      return 0;
    }else{
      wd++;
      if(wd > WD) return -1;
    }
  }
  }

//this need to be improved
void hw_aes_gcm_encrypt(void* aes_gcmctrl, uint64_t * output, uint64_t * input, size_t input_bytes, uint64_t* key, const size_t key_bytes, uint64_t * iv, const size_t iv_bytes, uint64_t * aad, const size_t aad_bytes,uint64_t * tag, size_t tag_bytes){
  if(key_bytes==32){
    hw_aes_gcm_set_key(aes_gcmctrl,key, AES_256_BIT_KEY);
  } 
  else if (key_bytes==16) {
    hw_aes_gcm_set_key(aes_gcmctrl,key, AES_128_BIT_KEY);
  }
  if(iv_bytes == 12){
    hw_aes_gcm_set_iiv(aes_gcmctrl,iv);
  }
  hw_aes_gcm_clear_block(aes_gcmctrl);
  hw_aes_gcm_clear_aad(aes_gcmctrl);
  hw_aes_gcm_ctrl(aes_gcmctrl,1,0,1,0); //start enc
  hw_aes_gcm_ctrl(aes_gcmctrl,1,1,1,0); //start enc
  hw_aes_gcm_wait_ready(aes_gcmctrl);
  hw_aes_gcm_ctrl(aes_gcmctrl,1,0,1,0); //start enc
  int aad_blocks = (aad_bytes + 15) / 16;
  for (int i=0; i< aad_blocks;i++){ //round up, need improve 
    // printf("aad %016llx\n", ((uint64_t*)(aad + (i * 2)))[0]);
    hw_aes_gcm_set_aad(aes_gcmctrl,aad+(i*2));
    hw_aes_gcm_ctrl(aes_gcmctrl,1,1,1,0); //start enc
    #ifdef AES_SMALL    
    hw_aes_gcm_wait_ready(aes_gcmctrl);
    #endif
    hw_aes_gcm_ctrl(aes_gcmctrl,1,0,1,0);
  }
  hw_aes_gcm_clear_aad(aes_gcmctrl);
  // printf("hw_aes_gcm_encrypt: input_bytes = %zu, aad_bytes = %zu\n", input_bytes, aad_bytes);
  /* Process plaintext blocks */
  int input_blocks = (input_bytes + 15) / 16;
  for (int i = 0; i < input_blocks; i++) {
    size_t valid_bytes = 16;
    if (i == input_blocks - 1 && input_bytes % 16) {
      valid_bytes = input_bytes % 16;  /* Last partial block */
    }
    
    // printf("Processing block %d with %lu valid bytes\n", i, (unsigned long)valid_bytes);
    /* Set block with proper byte count */
    hw_aes_gcm_set_block(aes_gcmctrl, input + (i * 2), valid_bytes);
    
    hw_aes_gcm_ctrl(aes_gcmctrl, 1, 1, 1, 0);
    hw_aes_gcm_read_result(aes_gcmctrl, output + (i * 2));
    hw_aes_gcm_wait_ready(aes_gcmctrl);
    hw_aes_gcm_ctrl(aes_gcmctrl, 1, 0, 1, 0);
  }
  hw_aes_gcm_clear_block(aes_gcmctrl);
  uint64_t len [2]= {aad_bytes * 8, input_bytes * 8}; // bit lengths
  // printf("aad_bytes %lu\n", aad_bytes);
  // printf("input_bytes %lu\n", input_bytes);
  // printf("GCM: finalizing with AAD length %lu bits and input length %lu bits\n", len[0], len[1]);
  hw_aes_gcm_set_aad(aes_gcmctrl,len);
  hw_aes_gcm_ctrl(aes_gcmctrl,1,1,1,0); //start enc
  hw_aes_gcm_read_tag(aes_gcmctrl,tag); //get tag
  hw_aes_gcm_wait_ready(aes_gcmctrl);
  hw_aes_gcm_ctrl(aes_gcmctrl,1,0,1,0);
}

int hw_aes_gcm_decrypt_verify(void* aes_gcmctrl, uint64_t * output, const uint64_t * input, size_t input_bytes,
                              const uint64_t* key, size_t key_bytes, const uint64_t * iv, size_t iv_bytes,
                              const uint64_t * aad, size_t aad_bytes, const uint64_t * tag, size_t tag_bytes)
{
    if (key_bytes == 32) hw_aes_gcm_set_key(aes_gcmctrl, (uint64_t*)key, AES_256_BIT_KEY);
    else if (key_bytes == 16) hw_aes_gcm_set_key(aes_gcmctrl, (uint64_t*)key, AES_128_BIT_KEY);
    if (iv_bytes  == 12) hw_aes_gcm_set_iiv(aes_gcmctrl, (uint64_t*)iv);

    hw_aes_gcm_clear_block(aes_gcmctrl);
    hw_aes_gcm_clear_aad(aes_gcmctrl);

    /* SET EXPECTED TAG FIRST - like the testbench */
    hw_aes_gcm_set_tag(aes_gcmctrl, (uint64_t*)tag);

    /* init decrypt */
    hw_aes_gcm_ctrl(aes_gcmctrl, 1, 0, DEC_MODE, 0);
    hw_aes_gcm_ctrl(aes_gcmctrl, 1, 1, DEC_MODE, 0);
    if (hw_aes_gcm_wait_ready(aes_gcmctrl) != 0) { printf("GCM: ERR init wait\n"); return -1; }
    hw_aes_gcm_ctrl(aes_gcmctrl, 1, 0, DEC_MODE, 0);

    /* Clear tag after initial setup */
    hw_aes_gcm_clear_tag(aes_gcmctrl);

    /* feed AAD (round up to 128-bit blocks) */
    int aad_blocks = (aad_bytes + 15) / 16;
    for (int i = 0; i < aad_blocks; ++i) {
        // printf("aad %016llx\n", ((uint64_t*)(aad + (i * 2)))[0]);
        hw_aes_gcm_set_aad(aes_gcmctrl, (uint64_t*)(aad + (i * 2)));
        hw_aes_gcm_ctrl(aes_gcmctrl, 1, 1, DEC_MODE, 0);
#ifdef AES_SMALL
        if (hw_aes_gcm_wait_ready(aes_gcmctrl) != 0) { printf("GCM: ERR AAD wait\n"); return -2; }
#endif
        hw_aes_gcm_ctrl(aes_gcmctrl, 1, 0, DEC_MODE, 0);
    }
    hw_aes_gcm_clear_aad(aes_gcmctrl);

    /* process ciphertext blocks -> plaintext */
  int blocks = (input_bytes + 15) / 16;
  for (int i = 0; i < blocks; i++) {
    size_t valid_bytes = 16;
    if (i == blocks - 1 && input_bytes % 16) {
      valid_bytes = input_bytes % 16;  /* Last partial block */
    }
    // printf("Processing block %d with %lu valid bytes\n", i, (unsigned long)valid_bytes);
    hw_aes_gcm_set_block(aes_gcmctrl, (uint64_t*)(input + (i * 2)), valid_bytes);
    hw_aes_gcm_ctrl(aes_gcmctrl, 1, 1, DEC_MODE, 0);
    if (hw_aes_gcm_read_result(aes_gcmctrl, output + (i * 2)) != 0) { return -3; }
    if (hw_aes_gcm_wait_ready(aes_gcmctrl) != 0) { return -4; }
    hw_aes_gcm_ctrl(aes_gcmctrl, 1, 0, DEC_MODE, 0);
  }

    /* finalize: lengths (bits) only */
    uint64_t len_words[2] = {aad_bytes * 8, input_bytes * 8};
    // printf("aad_bytes %lu\n", aad_bytes);
    // printf("input_bytes %lu\n", input_bytes);
    // printf("GCM: finalizing with AAD length %lu bits and input length %lu bits\n", len_words[0], len_words[1]);
    hw_aes_gcm_set_aad(aes_gcmctrl, len_words);
    hw_aes_gcm_ctrl(aes_gcmctrl, 1, 1, DEC_MODE, 0);
    if (hw_aes_gcm_wait_ready(aes_gcmctrl) != 0) { printf("GCM: ERR final wait\n"); return -5; }

    return hw_aes_gcm_authentic(aes_gcmctrl) ? 0 : -6;
}



void hwaesgcm_selftest(void* aes_gcmctrl){

  uint64_t key[4] = { (0xE3C08A8FLL << 32) | 0x06C6E3ADLL, (0x95A70557LL << 32) | 0xB23F7548LL, (0x3CE33021LL << 32) | 0xA9C72B70LL, (0x25666204LL << 32) | 0xC69C0B72LL };
  uint64_t plaintext[6] = { (0x08000F10LL << 32) | 0x11121314LL, (0x15161718LL << 32) | 0x191A1B1CLL, (0x1D1E1F20LL << 32) | 0x21222324LL, (0x25262728LL << 32) | 0x292A2B2CLL, (0x2D2E2F30LL << 32) | 0x31323334LL, (0x35363738LL << 32) | 0x393A0000LL };
  uint64_t aad[4] =   { (0xD609B1F0LL << 32) | 0x56637A0DLL, (0x46DF998DLL << 32) | 0x88E52E00LL, (0xB2C28465LL << 32) | 0x12153524LL, (0xC0895E81LL << 32) | 0x00000000LL };
  uint64_t iv[2] = { (0x12153524LL << 32) | 0xC0895E81LL, 0xB2C28465LL };
  uint64_t tag [2] ={0,0};
  uint64_t ciphertext[6];
  
  uint64_t start_mtime;
  uint64_t delta_mtime;
//  start_mtime = clkutils_read_mtime();
  //reset
  hw_aes_gcm_reset (aes_gcmctrl);
  hw_aes_gcm_encrypt(aes_gcmctrl, ciphertext, plaintext, 46, key, 32, iv, 12, aad, 28, tag, 16);
//  delta_mtime = clkutils_read_mtime() - start_mtime;
  int count = 0;
    for (int i = 0; i < 6; i++)
    {
        // uart_put_hex((void *)uart_reg, ciphertext[i] >> 32);
        // uart_put_hex((void *)uart_reg, ciphertext[i] & 0xFFFFFFFF);
        printf("%16llx", (ciphertext[i]));
        count += 2;
        if(count == 4){
          // uart_puts((void *)uart_reg, "\n");
          printf("\n");
          count = 0;
        }
        
    }
    // uart_puts((void*)uart_reg,"\n");
    count = 0;
    for (int i = 0; i < 2; i++)
    {
        // uart_put_hex((void *)uart_reg, tag[i] >> 32);
        // uart_put_hex((void *)uart_reg, tag[i] & 0xFFFFFFFF);
        printf("%08llx %08llx ", (tag[i] >> 32), (tag[i] & 0xFFFFFFFFLL));
        count += 2;
        if(count == 4){
          // uart_puts((void *)uart_reg, "\n");
          printf("\n");
          count = 0;
        }
        
    }
  // uart_puts((void*)uart_reg,"\n");
//  printf("\r\nTime: ");
//  print_meas(delta_mtime);
//  printf("\n");
}

#ifndef HWAESGCM_TEST_BYTES
/* default test size: 1 KiB (change at compile time with -DHWAESGCM_TEST_BYTES=...) */
#define HWAESGCM_TEST_BYTES (2 * 1024)
#endif

/* number of 64-bit words for the test buffer (constant for static allocation) */
#ifndef HWAESGCM_TEST_WORDS64
#define HWAESGCM_TEST_WORDS64 ((HWAESGCM_TEST_BYTES + 7) / 8)
#endif

/* how many 64-bit words to print from each buffer (keep small to avoid spam) */
#ifndef HWAESGCM_PRINT_QWORDS
#define HWAESGCM_PRINT_QWORDS 16
#endif

/* Static buffers for large self-test (avoid libc malloc/free on baremetal) */
static uint64_t hw_aes_plaintext_buf[HWAESGCM_TEST_WORDS64];
static uint64_t hw_aes_ciphertext_buf[HWAESGCM_TEST_WORDS64];
static uint64_t hw_aes_recovered_buf[HWAESGCM_TEST_WORDS64];

void hwaesgcm_1m_selftest(void* aes_gcmctrl){
  // printf("hwaesgcm_1m_selftest (static buffers)\n");

  uint64_t key[4] = { (0xE3C08A8FLL << 32) | 0x06C6E3ADLL, (0x95A70557LL << 32) | 0xB23F7548LL, (0x3CE33021LL << 32) | 0xA9C72B70LL, (0x25666204LL << 32) | 0xC69C0B72LL };
  uint64_t aad[4] = { (0xD609B1F0LL << 32) | 0x56637A0DLL, (0x46DF998DLL << 32) | 0x88E52E00LL, (0xB2C28465LL << 32) | 0x12153524LL, (0xC0895E81LL << 32) | 0x00000000LL };
  uint64_t iv[2]  = { (0x12153524LL << 32) | 0xC0895E81LL, 0xB2C28465LL };
  uint64_t tag[2] = {0,0};

  const size_t plain_bytes   = HWAESGCM_TEST_BYTES;            /* configurable */
  const size_t plain_words64 = HWAESGCM_TEST_WORDS64;          /* round up to words */
  const size_t buf_words64   = plain_words64;
  const size_t to_print      = (HWAESGCM_PRINT_QWORDS < buf_words64) ? HWAESGCM_PRINT_QWORDS : buf_words64;

  // printf("hwaesgcm_1m_selftest: using %zu bytes (%zu words)\n", plain_bytes, plain_words64);

  /* Use static buffers allocated above */
  uint64_t *plaintext  = hw_aes_plaintext_buf;
  uint64_t *ciphertext = hw_aes_ciphertext_buf;
  uint64_t *recovered  = hw_aes_recovered_buf;

  /* Fill pattern (avoid printing the whole buffer) */
  for (size_t i = 0; i < buf_words64; ++i) {
      plaintext[i] = (uint64_t)i;
  }
  printf("hwaesgcm_1m_selftest: plaintext initialized (pattern)\n");

  /* Print a small plaintext sample */
  printf("plaintext (first %llu qwords):\n", to_print);
  int count = 0;
  for (size_t i = 0; i < to_print; i++) {
      printf("%08llx %08llx ", (plaintext[i] >> 32), (plaintext[i] & 0xFFFFFFFFLL));
      if (++count == 4) { printf("\n"); count = 0; }
  }
  if (count) { printf("\n"); }

  /* reset and run */
  hw_aes_gcm_reset(aes_gcmctrl);
  hw_aes_gcm_encrypt(aes_gcmctrl,
                     ciphertext,
                     plaintext,
                     plain_bytes, /* input_bytes in bytes */
                     key, 32, iv, 12, aad, 28, tag, 16);

  /* Print a small ciphertext sample */
  printf("ciphertext (first %llu qwords):\n", to_print);
  count = 0;
  for (size_t i = 0; i < to_print; i++) {
      printf("%08llx %08llx ", (ciphertext[i] >> 32), (ciphertext[i] & 0xFFFFFFFFLL));
      if (++count == 4) { printf("\n"); count = 0; }
  }
  if (count) { printf("\n"); }

  hw_aes_gcm_reset(aes_gcmctrl);
  int ret = hw_aes_gcm_decrypt_verify(aes_gcmctrl, recovered, ciphertext, plain_bytes, key, 32, iv, 12, aad, 28, tag, 16);
  if (ret != 0) {
      printf("ROUNDTRIP: decrypt/verify failed (%d)\n", ret);
      return;
  }

  /* Print a small recovered sample */
  printf("recovered (first %llu qwords):\n", to_print);
  count = 0;
  for (size_t i = 0; i < to_print; i++) {
      printf("%08llx %08llx ", (recovered[i] >> 32), (recovered[i] & 0xFFFFFFFFLL));
      if (++count == 4) { printf("\n"); count = 0; }
  }
  if (count) { printf("\n"); }

  /* Quick mismatch scan (optional) */
  for (size_t i = 0; i < buf_words64; ++i) {
    if (recovered[i] != plaintext[i]) {
        printf("ROUNDTRIP: mismatch at qword %zu\n", i);
        break;
    }
  }

  printf("ROUNDTRIP: done\n");
}

int hwaesgcm_hw_roundtrip(void* aes_gcmctrl)
{
    printf("GCM: roundtrip begin\n");

  uint64_t key[4] = { (0xE3C08A8FLL << 32) | 0x06C6E3ADLL, (0x95A70557LL << 32) | 0xB23F7548LL, (0x3CE33021LL << 32) | 0xA9C72B70LL, (0x25666204LL << 32) | 0xC69C0B72LL };
  uint64_t plaintext[6] = { (0x08000F10LL << 32) | 0x11121314LL, (0x15161718LL << 32) | 0x191A1B1CLL, (0x1D1E1F20LL << 32) | 0x21222324LL, (0x25262728LL << 32) | 0x292A2B2CLL, (0x2D2E2F30LL << 32) | 0x31323334LL, (0x35363738LL << 32) | 0x393A0002LL };
  uint64_t aad[4] = { (0xD609B1F0LL << 32) | 0x56637A0DLL, (0x46DF998DLL << 32) | 0x88E52E00LL, (0xB2C28465LL << 32) | 0x12153524LL, (0xC0895E81LL << 32) | 0x00000000LL };
  uint64_t iv[2] = { (0x12153524LL << 32) | 0xC0895E81LL, 0xB2C28465LL };
  uint64_t tag[2] = {0};
  uint64_t ciphertext[6] = {0};
  uint64_t recovered[6] = {0};

    hw_aes_gcm_reset(aes_gcmctrl);
    hw_aes_gcm_encrypt(aes_gcmctrl, ciphertext, plaintext, 48, key, 32, iv, 12, aad, 32, tag, 16);

      int count = 0;
      printf("ciphertext:\n");
    for (int i = 0; i < 6; i++)
    {
        printf("%08llx %08llx ", (ciphertext[i] >> 32), (ciphertext[i] & 0xFFFFFFFFLL));
        count += 2;
        if(count == 4){
          printf("\n");
          count = 0;
        }
        
    }
    printf("\n");
    count = 0;
    printf("tag:\n");
    for (int i = 0; i < 2; i++)
    {
        printf("%08llx %08llx ", (tag[i] >> 32), (tag[i] & 0xFFFFFFFFLL));
        count += 2;
        if(count == 4){
          printf("\n");
          count = 0;
        }
        
    }
    printf("GCM: enc done\n");

    /* decrypt + verify */
    hw_aes_gcm_reset(aes_gcmctrl);
    int ret = hw_aes_gcm_decrypt_verify(aes_gcmctrl, recovered, ciphertext, 48, key, 32, iv, 12, aad, 32, tag, 16);
    if (ret != 0) { printf("GCM: dec FAIL (%d)\n", ret); return ret; }
    printf("GCM: dec OK\n");

    count = 0;
    printf("recovered:\n");
    for (int i = 0; i < 6; i++)
    {
        printf("%08llx %08llx ", (recovered[i] >> 32), (recovered[i] & 0xFFFFFFFFLL));
        count += 2;
        if(count == 4){
          printf("\n");
          count = 0;
        }
        
    }

    for (int i = 0; i < 6; ++i) {
        if (recovered[i] != plaintext[i]) {
            printf("ROUNDTRIP: mismatch at word %d\n", i);

        }
    }
    printf("GCM: roundtrip done\n");
    return 0;
}

/* Testcase 2: AES-GCM Encryption 128-bit Key with AAD and Plaintext
 * KEY:  AD7A2BD03EAC835A6F620FDCB506B345 (upper 128 bits zero)
 * IV:   12153524C0895E81B2C28465 (96-bit)
 * AAD:  D609B1F056637A0D46DF998D88E52E00 B2C2846512153524C0895E81 00000000 (last 32 bits padding, not counted)
 * PT:   3 blocks (48 bytes)
 * LEN(A,C): aad_bits=0xE0 (28 bytes), ct_bits=0x180 (48 bytes)
 */
void hwaesgcm_testcase2_aes128(void* aes_gcmctrl)
{
  uint64_t key[4] = {
    (0xAD7A2BD0LL << 32) | 0x3EAC835ALL,
    (0x6F620FDCLL << 32) | 0xB506B345LL,
    0x0000000000000000ULL,
    0x0000000000000000ULL
  };
  uint64_t iv[2]  = { (0x12153524LL << 32) | 0xC0895E81LL, 0xB2C28465ULL };
  uint64_t aad[4] = {
    (0xD609B1F0LL << 32) | 0x56637A0DLL,
    (0x46DF998DLL << 32) | 0x88E52E00LL,
    (0xB2C28465LL << 32) | 0x12153524LL,
    (0xC0895E81LL << 32) | 0x00000000LL
  };
  uint64_t pt[6]  = {
    (0x08000F10LL << 32) | 0x11121314LL,
    (0x15161718LL << 32) | 0x191A1B1CLL,
    (0x1D1E1F20LL << 32) | 0x21222324LL,
    (0x25262728LL << 32) | 0x292A2B2CLL,
    (0x2D2E2F30LL << 32) | 0x31323334LL,
    (0x35363738LL << 32) | 0x393A0000LL
  };
  uint64_t ct[6] = {0};
  uint64_t tag[2] = {0};
  uint64_t rec[6] = {0};

  const size_t aad_bytes = 28;  /* 224 bits as specified */
  const size_t pt_bytes  = 46;  /* 368 bits */

  hw_aes_gcm_reset(aes_gcmctrl);
  hw_aes_gcm_encrypt(aes_gcmctrl, ct, pt, pt_bytes, key, 16, iv, 12, aad, aad_bytes, tag, 16);

  int count = 0;
  printf("TC2-128 enc: ciphertext\n");
  for (int i = 0; i < 6; i++) {
    printf("%08llx %08llx ", (ct[i] >> 32), (ct[i] & 0xFFFFFFFFULL));
    if ((++count & 3) == 0) printf("\n");
  }
  if (count & 3) printf("\n");
  printf("TC2-128 enc: tag\n%08llx %08llx\n", (tag[0] >> 32), (tag[0] & 0xFFFFFFFFULL));
  printf("%08llx %08llx\n", (tag[1] >> 32), (tag[1] & 0xFFFFFFFFULL));

  hw_aes_gcm_reset(aes_gcmctrl);
  int ret = hw_aes_gcm_decrypt_verify(aes_gcmctrl, rec, ct, pt_bytes, key, 16, iv, 12, aad, aad_bytes, tag, 16);
  if (ret != 0) {
    printf("TC2-128 dec FAIL (%d)\n", ret);
    return;
  }

  int mismatch = 0;
  for (int i = 0; i < 6; ++i) {
    if (rec[i] != pt[i]) { printf("TC2-128 mismatch @%d\n", i); mismatch = 1; break; }
  }
  if (!mismatch) printf("TC2-128 roundtrip OK\n");
}