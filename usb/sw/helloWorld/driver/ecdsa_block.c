/* See the file LICENSE for further information */

// #include "encoding.h"
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
#include <stdint.h>
#include "include/platform.h"
#include "kprintf.h"
#include <string.h>
#include "driver/uart/uart.h"


//#define TEST_PRIMITIVE 1
//#define DEBUG 1
#define NUM_DIGITS 8
// software helper
uint32_t sw_add(uint32_t *p_result, uint32_t *p_left, uint32_t *p_right)
{
    uint32_t l_carry = 0;
    uint32_t i;
    for(i=0; i<NUM_DIGITS; ++i)
    {
        uint32_t l_sum = p_left[i] + p_right[i] + l_carry;
        if(l_sum != p_left[i])
        {
            l_carry = (l_sum < p_left[i]);
        }
        p_result[i] = l_sum;
    }
    return l_carry;
}
//p_left<=p_right
void sw_copy(uint32_t *p_left, uint32_t *p_right)
{
    for(int i=0; i<NUM_DIGITS; ++i)
    {
            p_left[i] = p_right[i];
    }
}

int sw_cmp(uint32_t *p_left, uint32_t *p_right)
{
    int i;
    for(i = NUM_DIGITS-1; i >= 0; --i)
    {
        if(p_left[i] > p_right[i])
        {
            return 1;
        }
        else if(p_left[i] < p_right[i])
        {
            return -1;
        }
    }
    return 0;
}

uint32_t sw_sub(uint32_t *p_result, uint32_t *p_left, uint32_t *p_right)
{
    uint32_t l_borrow = 0;
    uint32_t i;
    for(i=0; i<NUM_DIGITS; ++i)
    {
        uint32_t l_diff = p_left[i] - p_right[i] - l_borrow;
        if(l_diff != p_left[i])
        {
            l_borrow = (l_diff > p_left[i]);
        }
        p_result[i] = l_diff;
    }
    return l_borrow;
}

void sw_modAdd(uint32_t *p_result, uint32_t *p_left, uint32_t *p_right, uint32_t *p_mod)
{
    uint32_t l_carry = sw_add(p_result, p_left, p_right);
    if(l_carry || sw_cmp(p_result, p_mod) >= 0)
    { /* p_result > p_mod (p_result = p_mod + remainder), so subtract p_mod to get remainder. */
        sw_sub(p_result, p_result, p_mod);
    }
}

//end software helper
void hw_scalar_point(void* ecdsa_blockctrl,uint32_t * scalar, uint32_t * point_x, uint32_t * point_y ){
  //set reset
  _REG32((char*)ecdsa_blockctrl, IN_GEN_POINT_RESET) = 1;
  //put scalar
  for (int i =0; i<8; i++){
     _REG32((char*)ecdsa_blockctrl, IN_S_0+(i<<2)) =scalar[i];
     _REG32((char*)ecdsa_blockctrl, IN_POINT_X_0+(i<<2)) =point_x[i];
     _REG32((char*)ecdsa_blockctrl, IN_POINT_Y_0 +(i<<2)) =point_y[i];
  }
  //release reset
  _REG32((char*)ecdsa_blockctrl, IN_GEN_POINT_RESET) = 0;
}

int hw_get_scalar_point(void* ecdsa_blockctrl, uint32_t * point_x, uint32_t * point_y){
    if( _REG32((char*)ecdsa_blockctrl, DONE_POINT) == 1){
    //putpoint x
    for (int i =0; i<8; i++){
       //hwecdsa_results(ecdsa_blockctrl);
       point_x[i] = _REG32((char*)ecdsa_blockctrl, OUT_POINT_X_0+(i<<2));
       point_y[i] = _REG32((char*)ecdsa_blockctrl, OUT_POINT_Y_0 +(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

void hw_modular_inverse(void* ecdsa_blockctrl,uint32_t * in_modInv){
  //set reset
  _REG32((char*)ecdsa_blockctrl, IN_MODINV_RESET) = 1;
  //put value
  for (int i =0; i<8; i++){
     _REG32((char*)ecdsa_blockctrl, IN_MODINV_0+(i<<2)) =in_modInv[i];
  }
  //release reset
  _REG32((char*)ecdsa_blockctrl, IN_MODINV_RESET) = 0;
}

int hw_get_modular_inverse(void* ecdsa_blockctrl, uint32_t * out_modInv){
    if( _REG32((char*)ecdsa_blockctrl, DONE_MODINV) == 1){
    //
    for (int i =0; i<8; i++){
       out_modInv[i] = _REG32((char*)ecdsa_blockctrl, OUT_MODINV_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}

void hw_multmod(void* ecdsa_blockctrl,uint32_t * a, uint32_t * b){
  //set reset
  _REG32((char*)ecdsa_blockctrl, IN_RESET_MODMULT) = 1;
  //putp a
  for (int i =0; i<8; i++){
     _REG32((char*)ecdsa_blockctrl, IN_A_MODMULT_0+(i<<2)) =a[i];
     _REG32((char*)ecdsa_blockctrl, IN_B_MODMULT_0 +(i<<2)) =b[i];
  }
  //release reset
  _REG32((char*)ecdsa_blockctrl, IN_RESET_MODMULT) = 0;
}

int hw_get_multmod(void* ecdsa_blockctrl, uint32_t * produc){
    if( _REG32((char*)ecdsa_blockctrl, DONE_MODMULT) == 1){
    //
    for (int i =0; i<8; i++){
       produc[i] = _REG32((char*)ecdsa_blockctrl, OUT_MODMULT_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}
//TODO: be sure a != b
void hw_point_add(void* ecdsa_blockctrl,uint32_t * p_x, uint32_t * p_y,uint32_t * q_x, uint32_t * q_y){
  //set reset
  _REG32((char*)ecdsa_blockctrl, IN_RESET_ADD) = 1;
  //putp p_x
  for (int i =0; i<8; i++){
     _REG32((char*)ecdsa_blockctrl, IN_P_X_0+(i<<2)) =p_x[i];
     _REG32((char*)ecdsa_blockctrl, IN_P_Y_0 +(i<<2)) =p_y[i];
     _REG32((char*)ecdsa_blockctrl, IN_Q_X_0+(i<<2)) =q_x[i];
     _REG32((char*)ecdsa_blockctrl, IN_Q_Y_0 +(i<<2)) =q_y[i];
  }
  //release reset
  _REG32((char*)ecdsa_blockctrl, IN_RESET_ADD) = 0;
}

int hw_get_point_add(void* ecdsa_blockctrl, uint32_t * r_x,uint32_t * r_y ){
    if( _REG32((char*)ecdsa_blockctrl, DONE_ADD) == 1){
    //
    for (int i =0; i<8; i++){
       r_x[i] = _REG32((char*)ecdsa_blockctrl, OUT_R_X_0+(i<<2));
       r_y[i] =_REG32((char*)ecdsa_blockctrl, OUT_R_Y_0+(i<<2));
    }
    return 0;
  } else {
    return -1;
  }
}


void hw_ecdsa_sign (void* ecdsa_blockctrl, uint32_t * priv_key, uint32_t * hash, uint32_t * k,uint32_t * s, uint32_t * r ){
  uint32_t n[8]={0xfc632551,0xf3b9cac2,0xa7179e84,0xbce6faad,0xffffffff,0xffffffff,0x00000000,0xffffffff}; 
  uint32_t temp[8];
  uint32_t priv_key_x[8] = {0xd898c296,0xf4a13945,0x2deb33a0,0x77037d81,0x63a440f2,0xf8bce6e5,0xe12c4247,0x6b17d1f2};
  uint32_t priv_key_y[8] = {0x37bf51f5,0xcbb64068,0x6b315ece,0x2bce3357,0x7c0f9e16,0x8ee7eb4a,0xfe1a7f9b,0x4fe342e2};

  hw_scalar_point(ecdsa_blockctrl,k, priv_key_x, priv_key_y);
  while(hw_get_scalar_point(ecdsa_blockctrl, priv_key_x, priv_key_y)!=0){}

  hw_modular_inverse(ecdsa_blockctrl,k);
  sw_copy(r,priv_key_x);
  if(sw_cmp(n, r) != 1)
        {
            sw_sub(r,r, n);
        }
  //print temp
  #ifdef DEBUG
  uart_puts((void*)uart, " \n k \n");
  int count = 0;
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, k[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  #endif
  //
  while(hw_get_modular_inverse(ecdsa_blockctrl,temp) != 0){}
  //print temp
  #ifdef DEBUG
  uart_puts((void*)uart, " \n k-1 \n");
  count = 0;
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, temp[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  #endif 
  //
  hw_multmod(ecdsa_blockctrl, priv_key,r);
  while(hw_get_multmod(ecdsa_blockctrl,s) != 0){}
  //print temp
  #ifdef DEBUG
  uart_puts((void*)uart, " \n s = r*privkey \n");
  count = 0;
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, s[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  #endif
  //
  //s=s+hash (software)
  sw_modAdd(s,s,hash,n);
  //print temp
  #ifdef DEBUG
  uart_puts((void*)uart, " \n s = s+hash mod n \n");
  count = 0;
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, s[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  #endif
  //
  hw_multmod(ecdsa_blockctrl, s,temp);
  while(hw_get_multmod(ecdsa_blockctrl,s) != 0){}
}

int hw_ecdsa_verify (void* ecdsa_blockctrl,uint32_t * p_publicKey_x,uint32_t * p_publicKey_y, uint32_t * p_signature_s,uint32_t * p_signature_r,uint32_t * hash){
  uint32_t u[8];
  uint32_t v[8];
  uint32_t g_x[8] ={0xd898c296,0xf4a13945,0x2deb33a0,0x77037d81,0x63a440f2,0xf8bce6e5,0xe12c4247,0x6b17d1f2};
  uint32_t g_y[8] ={0x37bf51f5,0xcbb64068,0x6b315ece,0x2bce3357,0x7c0f9e16,0x8ee7eb4a,0xfe1a7f9b,0x4fe342e2};
  uint32_t n[8]={0xfc632551,0xf3b9cac2,0xa7179e84,0xbce6faad,0xffffffff,0xffffffff,0x00000000,0xffffffff};
  uint32_t q_x[8];
  uint32_t q_y[8];
  // u = s_1
  hw_modular_inverse(ecdsa_blockctrl,p_signature_s);
  while(hw_get_modular_inverse(ecdsa_blockctrl,u) != 0){}
  //print temp
  #ifdef DEBUG
  uart_puts((void*)uart, " \n s_1 \n");
  int count = 0;
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, u[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  #endif
  //
  //v = hash*s_1
  hw_multmod(ecdsa_blockctrl, hash,u);
  while(hw_get_multmod(ecdsa_blockctrl,v) != 0){}
  //print temp
  #ifdef DEBUG
  uart_puts((void*)uart, " \n v = s_1*hash mod n \n");
  count = 0;
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, v[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  #endif
  //
  //u = r*s_1
  hw_multmod(ecdsa_blockctrl, p_signature_r,u);
  while(hw_get_multmod(ecdsa_blockctrl,u) != 0){}
  //print temp
  #ifdef DEBUG
  uart_puts((void*)uart, " \n u = s_1*r mod n \n");
  count = 0;
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, u[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  #endif
  //
  // (q)= u*(pub_key)
  hw_scalar_point(ecdsa_blockctrl, u, p_publicKey_x, p_publicKey_y );
  while(hw_get_scalar_point(ecdsa_blockctrl,q_x,q_y) != 0){}
  //print temp
  #ifdef DEBUG
  uart_puts((void*)uart, " \n (q) = u * (pub_key) \n");
  count = 0;
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, q_x[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  #endif
  //
  // (g)= v*(g)
  hw_scalar_point(ecdsa_blockctrl, v,g_x ,g_y  );
  while(hw_get_scalar_point(ecdsa_blockctrl,g_x,g_y) != 0){}
  //print temp
  #ifdef DEBUG
  uart_puts((void*)uart, " \n (g) = v*(g) \n");
  count = 0;
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, g_x[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  #endif
  //
  //q=(q)+(g)
  //TODO:be sure q != g
  hw_point_add(ecdsa_blockctrl,q_x, q_y, g_x, g_y);
  while(hw_get_point_add(ecdsa_blockctrl, q_x,q_y)!=0){}
  //print temp
  #ifdef DEBUG
  uart_puts((void*)uart, " \n (q) = (q)+(g) \n");
  count = 0;
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, q_x[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  #endif
  //
  //q_x = q_x mod n
  if(sw_cmp(n, q_x) != 1)
        {
            sw_sub(q_x,q_x, n);
        }
  if(sw_cmp(p_signature_r,q_x)==0){
  return 0;
  }else{
  return -1;
  }
}

void hw_ecdsa_primitives_selftest(void* ecdsa_blockctrl){
  int count;
  #ifdef TEST_PRIMITIVE
  //
  uart_puts((void*)uart,"\n");
  uart_puts((void*)uart, "\r\nScalar Mult: ");
  uart_puts((void*)uart, "\n");
  uint32_t ss[8] =   {0xda72b464,0xca54a56d,0x0b4e3eac,0x5b44c813,0x59f4771a,0x1f4fa8ee,0x715f8b58,0x519b423d};
  uint32_t p_x[8] = {0xd898c296,0xf4a13945,0x2deb33a0,0x77037d81,0x63a440f2,0xf8bce6e5,0xe12c4247,0x6b17d1f2};
  uint32_t p_y[8] = {0x37bf51f5,0xcbb64068,0x6b315ece,0x2bce3357,0x7c0f9e16,0x8ee7eb4a,0xfe1a7f9b,0x4fe342e2};
  
//Gx      =       0x6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296
//Gy      =       0x4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5
//privKey       = 0x519b423d 715f8b58 1f4fa8ee 59f4771a 5b44c813 0b4e3eac ca54a56d da72b464
//px            = 0x1ccbe91c 075fc7f4 f033bfa2 48db8fcc d3565de9 4bbfb12f 3c59ff46 c271bf83
//py            = 0xce4014c6 8811f9a2 1a1fdb2c 0e6113e0 6db7ca93 b7404e78 dc7ccd5c a89a4ca9

  hw_scalar_point(ecdsa_blockctrl,ss, p_x, p_y);
  while(hw_get_scalar_point(ecdsa_blockctrl, p_x, p_y)!=0){}
  count = 0;
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, p_x[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }  
    count = 0;
    for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, p_y[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  
  uart_puts((void*)uart,"\n");
  uart_puts((void*)uart, "\r\nModular Inverse: ");
  uart_puts((void*)uart, "\n");
  uint32_t modInv[8] = {0xd898c296,0xf4a13945,0x2deb33a0,0x77037d81,0x63a440f2,0xf8bce6e5,0xe12c4247,0x6b17d1f2};
  //  in = 512'h      0x6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296

  hw_modular_inverse(ecdsa_blockctrl,modInv);
  while(hw_get_modular_inverse(ecdsa_blockctrl, modInv)!=0){}
  count = 0;
    for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, modInv[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  
  uart_puts((void*)uart,"\n");
  uart_puts((void*)uart, "\r\nModular mult: ");
  uart_puts((void*)uart, "\n");
  uint32_t a[8]={0xd898c296,0xf4a13945,0x2deb33a0,0x77037d81,0x63a440f2,0xf8bce6e5,0xe12c4247,0x6b17d1f2};
  uint32_t b[8]={0x37bf51f5,0xcbb64068,0x6b315ece,0x2bce3357,0x7c0f9e16,0x8ee7eb4a,0xfe1a7f9b,0x4fe342e2};

  //a =               0x6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296;
  //b =               0x4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5;

  hw_multmod(ecdsa_blockctrl,a,b);
  while(hw_get_multmod(ecdsa_blockctrl, a)!=0){}
  count = 0;
    for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, a[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }

  uart_puts((void*)uart,"\n");
  uart_puts((void*)uart, "\r\nPoint Add: ");
  uart_puts((void*)uart, "\n");
  uint32_t qq_x[8]={0xd898c296,0xf4a13945,0x2deb33a0,0x77037d81,0x63a440f2,0xf8bce6e5,0xe12c4247,0x6b17d1f2};
  uint32_t qq_y[8]={0x37bf51f5,0xcbb64068,0x6b315ece,0x2bce3357,0x7c0f9e16,0x8ee7eb4a,0xfe1a7f9b,0x4fe342e2};
  uint32_t pq_x[8]={0x47669978,0xa60b48fc,0x77f21b35,0xc08969e2,0x04b51ac3,0x8a523803,0x8d034f7e,0x7cf27b18};
  uint32_t pq_y[8]={0x227873d1,0x9e04b79d,0x3ce98229,0xba7dade6,0x9f7430db,0x293d9ac6,0xdb8ed040,0x07775510};

  //Q_x =             0x6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296;
  //Q_y =             0x4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5;
  //P_x =             0x7cf27b18 8d034f7e 8a523803 04b51ac3 c08969e2 77f21b35 a60b48fc 47669978;
  //P_y =             0x07775510 db8ed040 293d9ac6 9f7430db ba7dade6 3ce98229 9e04b79d 227873d1;

  hw_point_add(ecdsa_blockctrl,pq_x, pq_y, qq_x, qq_y);
  while(hw_get_point_add(ecdsa_blockctrl, pq_x,pq_y)!=0){}
  count = 0;
    for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, pq_x[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  count = 0;
    for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, pq_y[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  #endif
  //ecdsa secp256r1 test start
  /*
  Msg     =   5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8
  msghash =   44c65f3e 251d4223 ebca93c6 0637d7d7 0f50b225 f7c4e65e f0285e5e b0e253c6
  d       =   519b423d 715f8b58 1f4fa8ee 59f4771a 5b44c813 0b4e3eac ca54a56d da72b464
  Qx      =   1ccbe91c 075fc7f4 f033bfa2 48db8fcc d3565de9 4bbfb12f 3c59ff46 c271bf83
  Qy      =   ce4014c6 8811f9a2 1a1fdb2c 0e6113e0 6db7ca93 b7404e78 dc7ccd5c a89a4ca9
  k       =   94a1bbb1 4b906a61 a280f245 f9e93c7f 3b4a6247 824f5d33 b9670787 642a68de
  R       =   f3ac8061 b514795b 8843e3d6 629527ed 2afd6b1f 6a555a7a cabb5e6f 79c8c2ac
  S       =   8bf77819 ca05a6b2 786c7626 2bf7371c ef97b218 e96f175a 3ccdda2a cc058903

  msghash =   9b2db89c b0e8fa3c c7608b4d 6cc1dec0 114e0b9f f4080bea 12b134f4 89ab2bbc
  Msg     =   c35e2f092553c55772926bdbe87c9796827d17024dbb9233a545366e2e5987dd344deb72df987144b8c6c43bc41b654b94cc856e16b96d7a821c8ec039b503e3d86728c494a967d83011a0e090b5d54cd47f4e366c0912bc808fbb2ea96efac88fb3ebec9342738e225f7c7c2b011ce375b56621a20642b4d36e060db4524af1
  d       =   0f56db78 ca460b05 5c500064 824bed99 9a25aaf4 8ebb519a c201537b 85479813
  Qx      =   e266ddfd c12668db 30d4ca3e 8f774943 2c416044 f2d2b8c1 0bf3d401 2aeffa8a
  Qy      =   bfa86404 a2e9ffe6 7d47c587 ef7a97a7 f456b863 b4d02cfc 6928973a b5b1cb39
  k       =   6d3e7188 2c3b83b1 56bb14e0 ab184aa9 fb728068 d3ae9fac 421187ae 0b2f34c6
  R       =   976d3a4e 9d23326d c0baa9fa 560b7c4e 53f42864 f508483a 6473b6a1 1079b2db
  S       =   1b766e9c eb71ba6c 01dcd46e 0af462cd 4cfa652a e5017d45 55b8eeef e36e1932
  */                     
  //uint32_t hash[8]={b0e253c6,f0285e5e,f7c4e65e,0f50b225,0637d7d7,ebca93c6,251d4223,44c65f3e};
  //uint32_t d[8]   ={0xda72b464,0xca54a56d,0x0b4e3eac,0x5b44c813,0x59f4771a,0x1f4fa8ee,0x715f8b58,0x519b423d};
  //uint32_t k[8]   ={0x642a68de,0xb9670787,0x824f5d33,0x3b4a6247,0xf9e93c7f,0xa280f245,0x4b906a61,0x94a1bbb1};
       
  uint32_t hash[8]={0x89ab2bbc,0x12b134f4,0xf4080bea,0x114e0b9f,0x6cc1dec0,0xc7608b4d,0xb0e8fa3c,0x9b2db89c};
  uint32_t d[8]   ={0x85479813,0xc201537b,0x8ebb519a,0x9a25aaf4,0x824bed99,0x5c500064,0xca460b05,0x0f56db78};
  uint32_t k[8]   ={0x0b2f34c6,0x421187ae,0xd3ae9fac,0xfb728068,0xab184aa9,0x56bb14e0,0x2c3b83b1,0x6d3e7188};
   /*
            (0x6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296, 
             0x4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5)
  */
  uint32_t g_x[8] ={0xd898c296,0xf4a13945,0x2deb33a0,0x77037d81,0x63a440f2,0xf8bce6e5,0xe12c4247,0x6b17d1f2};
  uint32_t g_y[8] ={0x37bf51f5,0xcbb64068,0x6b315ece,0x2bce3357,0x7c0f9e16,0x8ee7eb4a,0xfe1a7f9b,0x4fe342e2};
  uint32_t r[8];
  uint32_t s[8];
  // uint64_t start_mtime;
  // uint64_t delta_mtime; 
  //gen key
  // start_mtime = clkutils_read_mtime();
  hw_scalar_point(ecdsa_blockctrl,d, g_x, g_y);
  while(hw_get_scalar_point(ecdsa_blockctrl, g_x, g_y)!=0){}
  // delta_mtime = clkutils_read_mtime() - start_mtime;
  count = 0;
  uart_puts((void*)uart, "Public key: \n");
  uart_puts((void*)uart, "X: \n");
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, g_x[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }  
  // uart_puts((void*)uart,"\n");
  // uart_puts((void*)uart, "\r\nTime key gen: ");
  // print_meas(delta_mtime);
  uart_puts((void*)uart, "\n");
  //signing
  // start_mtime = clkutils_read_mtime();
  hw_ecdsa_sign (ecdsa_blockctrl,d, hash,k,s, r );
  // delta_mtime = clkutils_read_mtime() - start_mtime;
  count = 0;
  uart_puts((void*)uart, "\r\nR:  \n");
  for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, r[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }  
    count = 0;
    uart_puts((void*)uart, "\r\nS:  \n");
    for (int i = 7; i >=0; i--)
    {
        uart_put_hex((void *)uart, s[i]);
        count++;
        if(count == 4){
          uart_puts((void *)uart, "\n");
          count = 0;
        }
    }
  // uart_puts((void*)uart,"\n");
  // uart_puts((void*)uart, "\r\nTime sign: ");
  // print_meas(delta_mtime);
  uart_puts((void*)uart, "\n");
  //verify
  // start_mtime = clkutils_read_mtime();
  if(hw_ecdsa_verify (ecdsa_blockctrl,g_x,g_y, s,r,hash)!=0){
    // delta_mtime = clkutils_read_mtime() - start_mtime;
    uart_puts((void*)uart, "Error verify");
  } else {
  // delta_mtime = clkutils_read_mtime() - start_mtime;
  uart_puts((void*)uart, "ECDSA secp256r1 finish");
  }
  // uart_puts((void*)uart,"\n");
  // uart_puts((void*)uart, "\r\nTime verify: ");
  // print_meas(delta_mtime);
  uart_puts((void*)uart, "\n");
  //end 
}
