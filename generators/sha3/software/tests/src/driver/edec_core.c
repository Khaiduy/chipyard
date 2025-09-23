/* See the file LICENSE for further information */

// // #include "encoding.h"
// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
// #include <stdatomic.h>
// #include "fdt/fdt_sifive.h"
// #include <uart/uart.h>
// #include <stdio.h>
// #include <platform.h>
// #include <barrier.h>
// #include <stdatomic.h>
// #include <devices/gpio.h>
// #include <spi/spi.h>
// #include <boot/boot.h>
// #include <gpt/gpt.h>
// #include <plic/plic_driver.h>
// #include "usb/usbtest.h"
// #include "clkutils.h"
// #include "common.h"
// #include "sha3/sha3.h"
// #include "lib/hmac_sha/sha2.h"

#include <stdint.h>
#include "include/platform.h"
#include "kprintf.h"
#include <string.h>
#include "driver/uart/uart.h"

//some usesfull defines
// working  table
#define MODE_ED 0
#define MODE_P256 1
#define MODE_P384 2
#define MODE_P521 3
// mode mode
#define   MODE_ECKGEN	0
#define 	MODE_ECSGEN1	1
#define 	MODE_ECSGEN2	2
#define 	MODE_ECVERF1	3
#define 	MODE_ECVERF2	4
#define   MODE_EDKGEN	  5
#define 	MODE_EDSGEN1	6
#define 	MODE_EDSGEN2	7
#define 	MODE_EDVERF1	8
#define 	MODE_EDVERF2	9
#define 	MODE_EDVERF3	10

//general func ecdsa

void uint32_t2bytes(byte * p_bytes, const uint32_t * p_native,int len)
{
    unsigned i;
    for(i=0; i<len; ++i)
    {
        byte *p_digit = p_bytes + 4 * (8 - 1 - i);
        p_digit[0] = p_native[i] >> 24;
        p_digit[1] = p_native[i] >> 16;
        p_digit[2] = p_native[i] >> 8;
        p_digit[3] = p_native[i];
    }
}
void bytes2uint32_t(uint32_t * p_native, const uint8_t * p_bytes, int len)
{
    unsigned i;
    for(i=0; i<len; ++i)
    {
        const uint8_t *p_digit = p_bytes + 4 * (8 - 1 - i);
        p_native[i] = ((uint32_t)p_digit[0] << 24) | ((uint32_t)p_digit[1] << 16) | ((uint32_t)p_digit[2] << 8) | ((uint32_t)p_digit[3] <<0);
    }
}

int hw_eddsa_reset_mem(void* edec_corectrl){

    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    
    for (int j=0; j<17; j++){
      _REG32((char*)edec_corectrl, IN_ADDR) = 16-j;
      for (int i =0; i<17; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =0;
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
    }
    _REG32((char*)edec_corectrl, IN_MODE) = 0;
    _REG32((char*)edec_corectrl, IN_WORKMODE) = 0;
    return 0;
}

int hw_ecdsa_set_r(void* edec_corectrl, int mode, uint32_t * k){
  if(mode < 4 && mode !=0 ){
    //set reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    //set start 0
    _REG32((char*)edec_corectrl, IN_START) = 0;
    //init 0
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    //set workmode and mode
    _REG32((char*)edec_corectrl, IN_WORKMODE) = mode;
    _REG32((char*)edec_corectrl, IN_MODE) = MODE_ECSGEN1;
    //release reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    //write k
    uint32_t len = 8;
    if      (mode ==MODE_P384) {len = 12;}
    else if (mode == MODE_P521){len = 17;}
    _REG32((char*)edec_corectrl, IN_ADDR) = 13;
    for (int i =0; i<len; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =k[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_START) = 1;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    return 0;
  }else{
    return -1;
  }
}

int hw_ecdsa_get_r(void* edec_corectrl, int mode, uint32_t * r ){
  if( _REG32((char*)edec_corectrl, OUT_READY)==1 && mode < 4 && mode !=0){
    uint32_t len = 8;
    if      (mode ==MODE_P384) {len = 12;}
    else if (mode == MODE_P521){len = 17;}
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    for (int i =0; i<len; i++){
       //hwecdsa_results(edec_corectrl);
       r[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

int hw_ecdsa_set_s (void* edec_corectrl, int mode,int use_r, uint32_t * priv_key, uint32_t * hash, uint32_t * k, uint32_t * r ){
  if(mode < 4 && mode !=0 ){
    //set reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    //set start 0
    _REG32((char*)edec_corectrl, IN_START) = 0;
    //init 0
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    //set workmode and mode
    _REG32((char*)edec_corectrl, IN_WORKMODE) = mode;
    _REG32((char*)edec_corectrl, IN_MODE) = MODE_ECSGEN2;
    //release reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    //write k
    uint32_t len = 8;
    if      (mode ==MODE_P384) {len = 12;}
    else if (mode == MODE_P521){len = 17;}
    if (use_r){
      _REG32((char*)edec_corectrl, IN_ADDR) = 0;
      for (int i =0; i<len; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =r[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
    }
    _REG32((char*)edec_corectrl, IN_ADDR) = 13;
    for (int i =0; i<len; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =k[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 14;
    for (int i =0; i<len; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =priv_key[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 15;
    for (int i =0; i<len; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =hash[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_START) = 1;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    return 0;
  }else{
    return -1;
  }
}

int hw_ecdsa_get_s(void* edec_corectrl, int mode, uint32_t * s ){
  if( _REG32((char*)edec_corectrl, OUT_READY)==1 && mode < 4 && mode !=0){
    uint32_t len = 8;
    if      (mode ==MODE_P384) {len = 12;}
    else if (mode == MODE_P521){len = 17;}
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    for (int i =0; i<len; i++){
       //hwecdsa_results(edec_corectrl);
       s[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

int hw_ecdsa_set_verify_1 (void* edec_corectrl, int mode, uint32_t * hash, uint32_t * s, uint32_t * r ){
  if(mode < 4 && mode !=0 ){
    //set reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    //set start 0
    _REG32((char*)edec_corectrl, IN_START) = 0;
    //init 0
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    //set workmode and mode
    _REG32((char*)edec_corectrl, IN_WORKMODE) = mode;
    _REG32((char*)edec_corectrl, IN_MODE) = MODE_ECVERF1;
    //release reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    //write k
    uint32_t len = 8;
    if      (mode ==MODE_P384) {len = 12;}
    else if (mode == MODE_P521){len = 17;}
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    for (int i =0; i<len; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =hash[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 1;
    for (int i =0; i<len; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =r[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 2;
    for (int i =0; i<len; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =s[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_START) = 1;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    return 0;
  }else{
    return -1;
  }
}

int hw_ecdsa_get_verify_1(void* edec_corectrl, int mode, uint32_t * u2, uint32_t * r0_x, uint32_t * r0_y ){
  if( _REG32((char*)edec_corectrl, OUT_READY)==1 && mode < 4 && mode !=0){
    uint32_t len = 8;
    if      (mode ==MODE_P384) {len = 12;}
    else if (mode == MODE_P521){len = 17;}
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 13;
    for (int i =0; i<len; i++){
       //hwecdsa_results(edec_corectrl);
       u2[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    _REG32((char*)edec_corectrl, IN_ADDR) = 14;
    for (int i =0; i<len; i++){
       //hwecdsa_results(edec_corectrl);
       r0_x[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    _REG32((char*)edec_corectrl, IN_ADDR) = 15;
    for (int i =0; i<len; i++){
       //hwecdsa_results(edec_corectrl);
       r0_y[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

int hw_ecdsa_set_verify_2 (void* edec_corectrl, int mode,int use1, uint32_t * a_x, uint32_t * a_y, uint32_t * u2, uint32_t * r_x, uint32_t * r_y ){
  if(mode < 4 && mode !=0 ){
    //set reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    //set start 0
    _REG32((char*)edec_corectrl, IN_START) = 0;
    //init 0
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    //set workmode and mode
    _REG32((char*)edec_corectrl, IN_WORKMODE) = mode;
    _REG32((char*)edec_corectrl, IN_MODE) = MODE_ECVERF2;
    //release reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    //write k
    uint32_t len = 8;
    if      (mode ==MODE_P384) {len = 12;}
    else if (mode == MODE_P521){len = 17;}
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    for (int i =0; i<len; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =a_x[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 1;
    for (int i =0; i<len; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =a_y[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    if(use1){
      _REG32((char*)edec_corectrl, IN_ADDR) = 13;
      for (int i =0; i<len; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =u2[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
      _REG32((char*)edec_corectrl, IN_ADDR) = 14;
      for (int i =0; i<len; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =r_x[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
      _REG32((char*)edec_corectrl, IN_ADDR) = 15;
      for (int i =0; i<len; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =r_y[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
      _REG32((char*)edec_corectrl, IN_ADDR) = 7;
      for (int i =0; i<len; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =0;
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
    }
    _REG32((char*)edec_corectrl, IN_START) = 1;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    return 0;
  }else{
    return -1;
  }
}

int hw_ecdsa_get_verify_2(void* edec_corectrl, int mode, uint32_t * v ){
  if( _REG32((char*)edec_corectrl, OUT_READY)==1 && mode < 4 && mode !=0){
    uint32_t len = 8;
    if      (mode ==MODE_P384) {len = 12;}
    else if (mode == MODE_P521){len = 17;}
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    for (int i =0; i<len; i++){
       //hwecdsa_results(edec_corectrl);
       v[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

// eddsa

int hw_eddsa_sign_1(void* edec_corectrl, int usepkey, uint32_t * pkey, uint32_t * a, uint32_t * r ){
    //set reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    //set start 0
    _REG32((char*)edec_corectrl, IN_START) = 0;
    //init 0
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    //set workmode and mode
    _REG32((char*)edec_corectrl, IN_WORKMODE) = MODE_ED;
    _REG32((char*)edec_corectrl, IN_MODE) = MODE_EDSGEN1;
    //release reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    //
    if(usepkey){
      _REG32((char*)edec_corectrl, IN_ADDR) = 12;
      for (int i =0; i<8; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =pkey[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
      _REG32((char*)edec_corectrl, IN_ADDR) = 13;
      for (int i =0; i<8; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =a[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
    }
    _REG32((char*)edec_corectrl, IN_ADDR) = 14;
    for (int i =0; i<8; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =r[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_START) = 1;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    return 0;
}

int hw_eddsa_get_sign_1(void* edec_corectrl, uint32_t * a, uint32_t * rs ){
  if( _REG32((char*)edec_corectrl, OUT_READY)==1){
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 11;
    for (int i =0; i<8; i++){
       //hwecdsa_results(edec_corectrl);
       a[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    _REG32((char*)edec_corectrl, IN_ADDR) = 12;
    for (int i =0; i<8; i++){
       //hwecdsa_results(edec_corectrl);
       rs[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

int hw_eddsa_sign_2 (void* edec_corectrl,int use_r, uint32_t * h, uint32_t * a, uint32_t * r){
    //set reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    //set start 0
    _REG32((char*)edec_corectrl, IN_START) = 0;
    //init 0
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    //set workmode and mode
    _REG32((char*)edec_corectrl, IN_WORKMODE) = MODE_ED;
    _REG32((char*)edec_corectrl, IN_MODE) = MODE_EDSGEN2;
    //release reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    for (int i =0; i<8; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =h[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;

    if (use_r){
      _REG32((char*)edec_corectrl, IN_ADDR) = 15;
      for (int i =0; i<8; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =a[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
      _REG32((char*)edec_corectrl, IN_ADDR) = 14;
      for (int i =0; i<8; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =r[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
    }
    
    _REG32((char*)edec_corectrl, IN_START) = 1;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    return 0;
}

int hw_eddsa_get_sign_2(void* edec_corectrl, uint32_t * s ){
  if( _REG32((char*)edec_corectrl, OUT_READY)==1){
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    for (int i =0; i<8; i++){
       //hwecdsa_results(edec_corectrl);
       s[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

int hw_eddsa_set_verify_1 (void* edec_corectrl, uint32_t * s){
    //set reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    //set start 0
    _REG32((char*)edec_corectrl, IN_START) = 0;
    //init 0
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    //set workmode and mode
    _REG32((char*)edec_corectrl, IN_WORKMODE) = MODE_ED;
    _REG32((char*)edec_corectrl, IN_MODE) = MODE_EDVERF1;
    //release reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    //write s
      _REG32((char*)edec_corectrl, IN_ADDR) = 13;
      for (int i =0; i<8; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =s[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_START) = 1;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    return 0;
}

int hw_eddsa_get_verify_1(void* edec_corectrl, uint32_t * sb_x, uint32_t * sb_y ){
  if( _REG32((char*)edec_corectrl, OUT_READY)==1 ){
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    for (int i =0; i<8; i++){
       //hwecdsa_results(edec_corectrl);
       sb_x[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    _REG32((char*)edec_corectrl, IN_ADDR) = 1;
    for (int i =0; i<8; i++){
       //hwecdsa_results(edec_corectrl);
       sb_y[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

int hw_eddsa_set_verify_2 (void* edec_corectrl,int usev1, uint32_t * h, uint32_t * pkey ){
    //set reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    //set start 0
    _REG32((char*)edec_corectrl, IN_START) = 0;
    //init 0
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    //set workmode and mode
    _REG32((char*)edec_corectrl, IN_WORKMODE) = MODE_ED;
    _REG32((char*)edec_corectrl, IN_MODE) = MODE_EDVERF2;
    //release reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    //
      _REG32((char*)edec_corectrl, IN_ADDR) = 13;
      for (int i =0; i<8; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =h[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
      _REG32((char*)edec_corectrl, IN_ADDR) = 12;
      for (int i =0; i<8; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =pkey[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;

    _REG32((char*)edec_corectrl, IN_START) = 1;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    return 0;
}

int hw_eddsa_get_verify_2(void* edec_corectrl, uint32_t * ha_x,  uint32_t * ha_y ){
  if( _REG32((char*)edec_corectrl, OUT_READY)==1 ){
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    for (int i =0; i<8; i++){
       ha_x[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    _REG32((char*)edec_corectrl, IN_ADDR) = 1;
    for (int i =0; i<8; i++){
       ha_y[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

int hw_eddsa_set_verify_3 (void* edec_corectrl,int usev2, uint32_t * rs, uint32_t * ha_x, uint32_t * ha_y ){
    //set reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    //set start 0
    _REG32((char*)edec_corectrl, IN_START) = 0;
    //init 0
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    //set workmode and mode
    _REG32((char*)edec_corectrl, IN_WORKMODE) = MODE_ED;
    _REG32((char*)edec_corectrl, IN_MODE) = MODE_EDVERF3;
    //release reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    //
    _REG32((char*)edec_corectrl, IN_ADDR) = 12;
      for (int i =0; i<8; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =rs[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
    if(usev2){
      _REG32((char*)edec_corectrl, IN_ADDR) = 14;
      for (int i =0; i<8; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =ha_x[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
      _REG32((char*)edec_corectrl, IN_ADDR) = 15;
      for (int i =0; i<8; i++){
        _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =ha_y[i];
      }
      _REG32((char*)edec_corectrl, IN_WE) = 1;
      _REG32((char*)edec_corectrl, IN_WE) = 0;
    }
    _REG32((char*)edec_corectrl, IN_START) = 1;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    return 0;
}

int hw_eddsa_get_verify_3(void* edec_corectrl, uint32_t * har_x,  uint32_t * har_y ){
  if( _REG32((char*)edec_corectrl, OUT_READY)==1 ){
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    for (int i =0; i<8; i++){
       har_x[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    _REG32((char*)edec_corectrl, IN_ADDR) = 1;
    for (int i =0; i<8; i++){
       har_y[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

void hw_wait_ready(void* edec_corectrl){
  while(_REG32((char*)edec_corectrl, OUT_READY)!=1 ){} 
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//ecdsa instructions
int hw_ecdsa_keygen(void* edec_corectrl,int mode, uint32_t * random_k){
  if(mode < 4 && mode !=0 ){
    //set reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    //set start 0
    _REG32((char*)edec_corectrl, IN_START) = 0;
    //init 0
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    //set workmode and mode
    _REG32((char*)edec_corectrl, IN_WORKMODE) = mode;
    _REG32((char*)edec_corectrl, IN_MODE) = MODE_ECKGEN;
    //release reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    //write k
    uint32_t len = 8;
    if      (mode ==MODE_P384) {len = 12;}
    else if (mode == MODE_P521){len = 17;}
    _REG32((char*)edec_corectrl, IN_ADDR) = 13;
    for (int i =0; i<len; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =random_k[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_START) = 1;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    return 0;
  }else{
    return -1;
  }
}

int hw_get_ecdsa_keygen(void* edec_corectrl,int mode, uint32_t * point_x, uint32_t * point_y){
    if( _REG32((char*)edec_corectrl, OUT_READY)==1 && mode < 4 && mode !=0){
    uint32_t len = 8;
    if      (mode ==MODE_P384) {len = 12;}
    else if (mode == MODE_P521){len = 17;}
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    for (int i =0; i<len; i++){
       //hwecdsa_results(edec_corectrl);
       point_x[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    _REG32((char*)edec_corectrl, IN_ADDR) = 1;
    for (int i =0; i<len; i++){
       //hwecdsa_results(edec_corectrl);
       point_y[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

int hw_ecdsa_signature (void* edec_corectrl, int mode, uint32_t * priv_key, uint32_t * hash, uint32_t * k,uint32_t * s, uint32_t * r ){
  if (hw_ecdsa_set_r(edec_corectrl,mode,k) == 0 ){
    while(hw_ecdsa_get_r(edec_corectrl,mode,r) != 0){}
    if (hw_ecdsa_set_s(edec_corectrl,mode,0,priv_key,hash,k,r) == 0 ){
    while(hw_ecdsa_get_s(edec_corectrl,mode,s) != 0){}
    } else {
    return -1;
    }
    return 0;
  }
  else{
    return -1;
  }
}
// return 1 if its verified, return 0 if not, and -1 if error 
int hw_ecdsa_verifed (void* edec_corectrl, int mode, uint32_t * p_publicKey_x,uint32_t * p_publicKey_y, uint32_t * p_signature_s,uint32_t * p_signature_r,uint32_t * hash,uint32_t * v){
  uint32_t len = 8;
  if      (mode ==MODE_P384) {len = 12;}
  else if (mode == MODE_P521){len = 17;}
  uint32_t u2[17],rx[17],ry[17];  //could be ignored
  //uint32_t v[17];
  if (hw_ecdsa_set_verify_1(edec_corectrl,mode,hash,p_signature_s,p_signature_r) == 0 ){
    while(hw_ecdsa_get_verify_1(edec_corectrl,mode,u2,rx,ry) != 0){}
    if (hw_ecdsa_set_verify_2(edec_corectrl,mode,0,p_publicKey_x,p_publicKey_y,u2,rx,ry) == 0 ){
    while(hw_ecdsa_get_verify_2(edec_corectrl,mode,v) != 0){}
    } else {
    return -1;
    }

    for(int i = 0; i < len; i++)
    {
        if(p_signature_r[i] != v[i])
        {   
            return 0;
        }
    }
    return 1;
  }
  else{
    return -1;
  }
}

//edDSA instructions

int hw_eddsa_keygen(void* edec_corectrl, uint32_t * random_k){
    //set reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 0;
    //set start 0
    _REG32((char*)edec_corectrl, IN_START) = 0;
    //init 0
    _REG32((char*)edec_corectrl, IN_ADDR) = 0;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    //set workmode and mode
    _REG32((char*)edec_corectrl, IN_WORKMODE) = MODE_ED;
    _REG32((char*)edec_corectrl, IN_MODE) = MODE_EDKGEN;
    //release reset
    _REG32((char*)edec_corectrl, IN_RESETN) = 1;
    //write k
    _REG32((char*)edec_corectrl, IN_ADDR) = 12;
    for (int i =0; i< 8; i++){
      _REG32((char*)edec_corectrl, IN_WDATA_0+(i<<2)) =random_k[i];
    }
    _REG32((char*)edec_corectrl, IN_WE) = 1;
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_START) = 1;
    _REG32((char*)edec_corectrl, IN_START) = 0;
    return 0;
}

int hw_get_eddsa_keygen(void* edec_corectrl, uint32_t * key){
    if( _REG32((char*)edec_corectrl, OUT_READY)==1){
    _REG32((char*)edec_corectrl, IN_WE) = 0;
    _REG32((char*)edec_corectrl, IN_ADDR) = 12;
    for (int i =0; i<8; i++){
       //hwecdsa_results(edec_corectrl);
       key[i] = _REG32((char*)edec_corectrl, OUT_RDATA_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

void hw_eddsa_signature(void* edec_corectrl, unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key, char red) {
    unsigned char hram[64];
    unsigned char r[64];
    unsigned char rred[64];

    sha512_ctx ctx; //TODO* replace for hardware
    sha512_init(&ctx);
    sha512_update(&ctx, private_key + 32, 32);
    sha512_update(&ctx, message, message_len);
    sha512_final(&ctx, r);

    for(int i = 0; i < 16; i++) {
        *(((uint32_t*)(rred)) + i) = *(((uint32_t*)(r)) + i);
    }
    if(red) sc_reduce(rred);

    uint32_t * hhash;
    uint32_t pkey[8];
    uint32_t A[128];
    uint32_t rs[128];
    bytes2uint32_t(pkey,public_key,8);
    uint32_t a[8];
    if(edec_corectrl != NULL){
        if (hw_eddsa_sign_1(edec_corectrl,0,pkey,a,(uint32_t*)rred) == 0 ){
        while(hw_eddsa_get_sign_1(edec_corectrl,A,rs) != 0){}
        }
    }
    //uint32_t -> bytes
    uint32_t2bytes(signature,rs,8);
    // Calculate the H(R, A, M)
    sha512_ctx ctx1;
    sha512_init(&ctx1);
    sha512_update(&ctx1, signature, 32);
    sha512_update(&ctx1, public_key, 32);
    sha512_update(&ctx1, message, message_len);
    sha512_final(&ctx1, hram);

    uint32_t s[8];

    sc_reduce(hram);

    hhash = (uint32_t*)hram;

    uint32_t aa[8];
    uint32_t rr[8];
    //
    if(edec_corectrl != NULL){
        if (hw_eddsa_sign_2(edec_corectrl,0,hhash,aa,rr) == 0 ){
        while(hw_eddsa_get_sign_2(edec_corectrl,s) != 0){}
        }
    }

    uint32_t2bytes(signature+32,s,8);
}

int hw_eddsa_verify(void* edec_corectrl, const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key) {
    unsigned char h[64];

    uint32_t pkey[8];
    uint32_t s[8] ;
    uint32_t sb_x[8];
    uint32_t sb_y[8];
    uint32_t ha_x[8];
    uint32_t ha_y[8];
    uint32_t har_x[8];
    uint32_t har_y[8];
    uint32_t rs[8];

    sha512_ctx hash;
    sha512_init(&hash);
    sha512_update(&hash, signature, 32);
    sha512_update(&hash, public_key, 32);
    sha512_update(&hash, message, message_len);
    sha512_final(&hash ,h);
    sc_reduce(h);

    bytes2uint32_t(pkey,public_key,8);
    bytes2uint32_t(rs,signature,8);
    bytes2uint32_t(s,signature+32,8);

    hw_eddsa_set_verify_1(edec_corectrl,s);
    while(hw_eddsa_get_verify_1(edec_corectrl,sb_x,sb_y) != 0){};

    hw_eddsa_set_verify_2(edec_corectrl,0,(uint32_t*)h,pkey);
    while(hw_eddsa_get_verify_2(edec_corectrl,ha_x,ha_y) != 0){};

    hw_eddsa_set_verify_3(edec_corectrl,0,rs,ha_x,ha_y);
    while(hw_eddsa_get_verify_3(edec_corectrl,har_x,har_y) != 0){};

    for(int i = 0; i < 8; i++)
    {
        if(sb_x[i] != har_x[i])
        {   
            return 0;
        }
        if(sb_y[i] != har_y[i])
        {   
            return 0;
        }
    }
    return 1;
}
////////////////////////////////////////////////////test

void hw_edec_ecdsa_256_selftest(void* edec_corectrl){
  //ecdsa secp256r1 test start
       
  uint32_t hash[8]={0x89ab2bbc,0x12b134f4,0xf4080bea,0x114e0b9f,0x6cc1dec0,0xc7608b4d,0xb0e8fa3c,0x9b2db89c};
  uint32_t d[8]   ={0x85479813,0xc201537b,0x8ebb519a,0x9a25aaf4,0x824bed99,0x5c500064,0xca460b05,0x0f56db78};
  uint32_t k[8]   ={0x0b2f34c6,0x421187ae,0xd3ae9fac,0xfb728068,0xab184aa9,0x56bb14e0,0x2c3b83b1,0x6d3e7188};

  uint32_t g_x[8];
  uint32_t g_y[8];
  uint32_t r[8];
  uint32_t s[8];
  uint64_t start_mtime;
  uint64_t delta_mtime; 
  //gen key
  start_mtime = clkutils_read_mtime();
  while(hw_ecdsa_keygen(edec_corectrl,MODE_P256,d)!=0){
    uart_puts((void*)uart_reg,"Invalid Input\n");
  }
  while(hw_get_ecdsa_keygen(edec_corectrl,MODE_P256, g_x, g_y)!=0){}
  delta_mtime = clkutils_read_mtime() - start_mtime;
  int count = 0;
  uart_puts((void*)uart_reg, "Public key: \n");
  uart_puts((void*)uart_reg, "X: \n");
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart_reg, g_x[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart_reg, "\n");
          count = 0;
        }
    }  
  uart_puts((void*)uart_reg, "\r\nTime key gen: ");
  print_meas(delta_mtime);
  uart_puts((void*)uart_reg, "\n");
  
  //signing
  
  start_mtime = clkutils_read_mtime();
  hw_ecdsa_signature (edec_corectrl,MODE_P256, d, hash,k,s,r );
  delta_mtime = clkutils_read_mtime() - start_mtime;
  count = 0;
  uart_puts((void*)uart_reg, "\r\nR:  \n");
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart_reg, r[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart_reg, "\n");
          count = 0;
        }
    }  
    count = 0;
    uart_puts((void*)uart_reg, "\r\nS:  \n");
    for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart_reg, s[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart_reg, "\n");
          count = 0;
        }
    }
  uart_puts((void*)uart_reg,"\n");
  uart_puts((void*)uart_reg, "\r\nTime sign: ");
  print_meas(delta_mtime);
  uart_puts((void*)uart_reg, "\n");
  
  //verify
  
  start_mtime = clkutils_read_mtime();
  uint32_t v[8];
  int status = hw_ecdsa_verifed (edec_corectrl,MODE_P256,g_x,g_y, s,r,hash,v);
  if(status==0){
    delta_mtime = clkutils_read_mtime() - start_mtime;
    uart_puts((void*)uart_reg, "Error verify");
  } else if(status == -1){
    delta_mtime = clkutils_read_mtime() - start_mtime;
    uart_puts((void*)uart_reg, "Error status");
  }
  else{
  delta_mtime = clkutils_read_mtime() - start_mtime;
  uart_puts((void*)uart_reg, "ECDSA secp256r1 finish");
  }
  uart_puts((void*)uart_reg,"\n");
  uart_puts((void*)uart_reg, "\r\nTime verify: ");
  print_meas(delta_mtime);
  uart_puts((void*)uart_reg, "\n");
  //end 
  
}

void hw_edec_ecdsa_384_selftest(void* edec_corectrl){
  //ecdsa secp384r1 test start
  uint32_t d[12]={
  0xb080ac97,
  0x29449f4f,
  0xccbce3bc,
  0x952f5db7,
  0xbdf45ec2,
  0x0da41e6c,
  0x82d52e37,
  0x46a82844,
  0xdb3e4b3f,
  0x182d6261,
  0x8df14324,
  0x201b432d};
  uint32_t hash[12]= {
  0xbd896825,  
  0xb344d81f,
  0xf0ed0bf2,
  0xebcc1a38,
  0x1085f17e,
  0xd58e020e,
  0xce9d4bc7,
  0xae705c29,
  0x8280231e,
  0xb5724c87,
  0x164d904b,
  0x31a452d6};
  uint32_t k[12]= {
  0x25c9c771,
  0x17c81e1f,
  0xe5bf97f9,
  0x8885e16c,
  0xa25283db,
  0x76a00f58,
  0x5ce28c66,
  0xdf9ded6e,
  0x6646fa34,
  0xf733c6e1,
  0x5978e090,
  0xdcedabf8};

  uint32_t g_x[12];
  uint32_t g_y[12];
  uint32_t r[12];
  uint32_t s[12];
  uint64_t start_mtime;
  uint64_t delta_mtime; 
  //gen key
  start_mtime = clkutils_read_mtime();
  while(hw_ecdsa_keygen(edec_corectrl,MODE_P384,d)!=0){
    uart_puts((void*)uart_reg,"Invalid Input\n");
  }
  while(hw_get_ecdsa_keygen(edec_corectrl,MODE_P384, g_x, g_y)!=0){}
  delta_mtime = clkutils_read_mtime() - start_mtime;
  int count = 0;
  uart_puts((void*)uart_reg, "Public key: \n");
  uart_puts((void*)uart_reg, "X: \n");
  for (int i = 11; i >=0; i--)
    {
        uart_put_hex((void *)uart_reg, g_x[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart_reg, "\n");
          count = 0;
        }
    }  

  uart_puts((void*)uart_reg, "\r\nTime key gen: ");
  print_meas(delta_mtime);
  uart_puts((void*)uart_reg, "\n");
  
  //signing
  
  start_mtime = clkutils_read_mtime();
  hw_ecdsa_signature (edec_corectrl,MODE_P384, d, hash,k,s,r );
  delta_mtime = clkutils_read_mtime() - start_mtime;
  count = 0;
  uart_puts((void*)uart_reg, "\r\nR:  \n");
  for (int i = 11; i >=0; i--)
    {
        uart_put_hex((void *)uart_reg, r[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart_reg, "\n");
          count = 0;
        }
    }  
    count = 0;
    uart_puts((void*)uart_reg, "\r\nS:  \n");
    for (int i = 11; i >=0; i--)
    {
        uart_put_hex((void *)uart_reg, s[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart_reg, "\n");
          count = 0;
        }
    }
  uart_puts((void*)uart_reg,"\n");
  uart_puts((void*)uart_reg, "\r\nTime sign: ");
  print_meas(delta_mtime);
  uart_puts((void*)uart_reg, "\n");
  
  //verify
  
  start_mtime = clkutils_read_mtime();
  uint32_t v[12];
  int status = hw_ecdsa_verifed (edec_corectrl,MODE_P384,g_x,g_y, s,r,hash,v);
  if(status==0){
    delta_mtime = clkutils_read_mtime() - start_mtime;
    uart_puts((void*)uart_reg, "Error verify");
  } else if(status == -1){
    delta_mtime = clkutils_read_mtime() - start_mtime;
    uart_puts((void*)uart_reg, "Error status");
  }
  else{
  delta_mtime = clkutils_read_mtime() - start_mtime;
  uart_puts((void*)uart_reg, "ECDSA secp384r1 finish");
  }
  uart_puts((void*)uart_reg,"\n");
  uart_puts((void*)uart_reg, "\r\nTime verify: ");
  print_meas(delta_mtime);
  uart_puts((void*)uart_reg, "\n");
  //end 
 
}

void hw_edec_ecdsa_521_selftest(void* edec_corectrl){
  //ecdsa secp521r1 test start
  uint32_t d[18]={
  0xa14cb926,  
  0x6c5e567a,
  0xcccf9fee,
  0x8c8655c0,
  0xc29a0f21,
  0x72f574cc,
  0xdca2359b,
  0x2fab0080,
  0x267ffaf0,
  0xed7db886,
  0x2678e515,
  0xba67f08d,
  0x103d8f4f,
  0x2cef0acf,
  0xbc533ca8,
  0x49d32704,
  0x000000f7,
  0x00000000};
  
  uint32_t hash[18]= {
  0x9a741047,  
  0xdcd63c4f,
  0xbfec3204,
  0x1af81de9,
  0x17e6e505,
  0x0cace7c2,
  0x0809712b,
  0x27c440e5,
  0x263f8016,
  0xf4bb6541,
  0xe00a36f3,
  0xbe01a81f,
  0xf03382c5,
  0xa599389d,
  0x092261bd,
  0x65f83408,
  0x00000000,
  0x00000000};
  
  uint32_t k[18]= {
  0x864c6df1,  
  0x83c7593e,
  0x33d4ecbb,
  0xec3f0aa7,
  0xdcf881fc,
  0xf3db9ac9,
  0xcf46cfe1,
  0x812d12fe,
  0xdddeac60,
  0x9be3053c,
  0xb5c60c76,
  0x17ffcd52,
  0x83c3b16a,
  0xa5bab9aa,
  0x29a6de86,
  0xf5ab6caa,
  0x0000003a,
  0x00000000};
  

  uint32_t g_x[18];
  uint32_t g_y[18];
  uint32_t r[18];
  uint32_t s[18];
  uint64_t start_mtime;
  uint64_t delta_mtime; 
  //gen key
  start_mtime = clkutils_read_mtime();
  while(hw_ecdsa_keygen(edec_corectrl,MODE_P521,d)!=0){
    uart_puts((void*)uart_reg,"Invalid Input\n");
  }
  while(hw_get_ecdsa_keygen(edec_corectrl,MODE_P521, g_x, g_y)!=0){}
  delta_mtime = clkutils_read_mtime() - start_mtime;
  int count = 0;
  uart_puts((void*)uart_reg, "Public key: \n");
  uart_puts((void*)uart_reg, "X: \n");
  for (int i = 16; i >=0; i--)
    {
        uart_put_hex((void *)uart_reg, g_x[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart_reg, "\n");
          count = 0;
        }
    }  

  uart_puts((void*)uart_reg, "\r\nTime key gen: ");
  print_meas(delta_mtime);
  uart_puts((void*)uart_reg, "\n");
  
  //signing
  
  start_mtime = clkutils_read_mtime();
  hw_ecdsa_signature (edec_corectrl,MODE_P521, d, hash,k,s,r );
  delta_mtime = clkutils_read_mtime() - start_mtime;
  count = 0;
  uart_puts((void*)uart_reg, "\r\nR:  \n");
  for (int i = 16; i >=0; i--)
    {
        uart_put_hex((void *)uart_reg, r[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart_reg, "\n");
          count = 0;
        }
    }  
    count = 0;
    uart_puts((void*)uart_reg, "\r\nS:  \n");
    for (int i = 16; i >=0; i--)
    {
        uart_put_hex((void *)uart_reg, s[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart_reg, "\n");
          count = 0;
        }
    }
  uart_puts((void*)uart_reg,"\n");
  uart_puts((void*)uart_reg, "\r\nTime sign: ");
  print_meas(delta_mtime);
  uart_puts((void*)uart_reg, "\n");
  
  //verify
  
  start_mtime = clkutils_read_mtime();
  uint32_t v[18];
  int status = hw_ecdsa_verifed (edec_corectrl,MODE_P521,g_x,g_y, s,r,hash,v);
  if(status==0){
    delta_mtime = clkutils_read_mtime() - start_mtime;
    uart_puts((void*)uart_reg, "Error verify");
  } else if(status == -1){
    delta_mtime = clkutils_read_mtime() - start_mtime;
    uart_puts((void*)uart_reg, "Error status");
  }
  else{
  delta_mtime = clkutils_read_mtime() - start_mtime;
  uart_puts((void*)uart_reg, "ECDSA secp521r1 finish");
  }
  uart_puts((void*)uart_reg,"\n");
  uart_puts((void*)uart_reg, "\r\nTime verify: ");
  print_meas(delta_mtime);
  uart_puts((void*)uart_reg, "\n");
  //end 
 
}

void hw_edec_eddsa_selftest(void* edec_corectrl){
  hw_eddsa_reset_mem(edec_corectrl);
  byte scratchpad_hw[128] = {0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60};
  byte signature[64];
  byte secret_key_hw[64];
  uint32_t secret_key_hw_32[8];
  byte public_key_hw[32];
  uint32_t public_key_hw_32[8];

  uart_puts((void*)uart_reg,"\r\nBegin ED25519 hardware test:\r\n");
  uint64_t start_mtime = clkutils_read_mtime();
  sha512(scratchpad_hw,32,secret_key_hw); //TODO: rerplace by hardware
  secret_key_hw[0] &= 248;
  secret_key_hw[31] &= 63;
  secret_key_hw[31] |= 64;
  bytes2uint32_t(secret_key_hw_32,secret_key_hw,8);
  while(hw_eddsa_keygen(edec_corectrl,secret_key_hw_32)!=0){
    uart_puts((void*)uart_reg,"Invalid Input\n");
  }
  while(hw_get_eddsa_keygen(edec_corectrl,((uint32_t*)public_key_hw_32))!=0){}
  uint64_t delta_mtime = clkutils_read_mtime() - start_mtime;
  uint32_t2bytes(public_key_hw,public_key_hw_32,8);
  uart_puts((void*)uart_reg, "Hardware gen key: ");
  print_meas(delta_mtime);
  uart_puts((void*)uart_reg, "Public key: \n");
  for(int i = 0; i < 32; i++)
    uart_put_hex_1b((void*)uart_reg, public_key_hw[i]);
  uart_puts((void*)uart_reg, "\r\nPrivate key: \n");
  for(int i = 32; i > 0 ; --i)
    uart_put_hex_1b((void*)uart_reg, secret_key_hw[i-1]);
  uart_puts((void*)uart_reg, "\n");
  for(int i = 32; i < 64; i++)
    uart_put_hex_1b((void*)uart_reg, secret_key_hw[i]);

  start_mtime = clkutils_read_mtime();
  hw_eddsa_signature(edec_corectrl, signature, scratchpad_hw,0, public_key_hw, secret_key_hw,1);
  delta_mtime = clkutils_read_mtime() - start_mtime;
  uart_puts((void*)uart_reg, "\r\nHardware sign: ");
  print_meas(delta_mtime);
  for(int i = 0; i < 64; i++){
    uart_put_hex_1b((void*)uart_reg, signature[i]);
    if(i == 31) uart_puts((void*)uart_reg, "\n");
  }
  start_mtime = clkutils_read_mtime();
  int status = hw_eddsa_verify(edec_corectrl, signature, scratchpad_hw, 0, public_key_hw);
  delta_mtime = clkutils_read_mtime() - start_mtime;
  uart_puts((void*)uart_reg, "\r\nVerification: ");
  print_meas(delta_mtime);
  if (status == 0){uart_puts((void*)uart_reg, "Verification fail");}
}