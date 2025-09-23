#include <stdint.h>
#include "include/platform.h"
//#include "kprintf.h"
#include <string.h>

#define HMAC_SHA_REG_CONF_DATA  0X100
// #define HMAC_SHA_REG_CONF_DATA_1  0X108
#define HMAC_SHA_REG_CONF_ADDRESS 0X108
#define HMAC_SHA_REG_DOUT       0X110
// #define HMAC_SHA_REG_DOUT_1       0X120
#define HMAC_SHA_REG_CONF_WE      0X118
#define HMAC_SHA_REG_INPUT_READY  0X120
#define HMAC_SHA_REG_END_PACKET   0X128
#define HMAC_SHA_REG_RESETN       0X130
#define HMAC_SHA_REG_READY        0X138
#define HMAC_SHA_REG_ENABLE       0X140

#define REG32(p, i) ((p)[(i) >> 2])
#define _REG64(p, i) (*(volatile uint64_t *)((p) + (i)))
#define _REG32(p, i) (*(volatile uint32_t *)((p) + (i)))
#define _REG16(p, i) (*(volatile uint16_t *)((p) + (i)))

//#define X25519_CTRL_ADDR _AC(0x64005000,UL)
//#define X25519_CTRL_SIZE _AC(0x1000,UL)
//static volatile uint64_t * const x25519 = (void *)(X25519_CTRL_ADDR);
//extern uintptr_t X25519_reg;

/* Function declarations */
//void hwx25519_init(void* x25519ctrl, uint64_t scalar[4], uint64_t point_in[4]);
//void hwx25519_results(void* x25519ctrl, uint64_t* result);
//void hwx25519_reset(void* x25519ctrl);
//void hwx25519_selftest(void* x25519ctrl);

//void print_x25519_value(const char* label, uint64_t* value);  // Optional helper