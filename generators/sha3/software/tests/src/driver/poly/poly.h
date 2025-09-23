/* See the file LICENSE for further information */

#include <stdint.h>
#include "include/platform.h"
//#include "kprintf.h"
#include <string.h>
//#include "driver/uart/uart.h"

/* Register offsets */
#define POLY_REG_KEY_0            0x100
#define POLY_REG_KEY_1            0x104
#define POLY_REG_KEY_2            0x108
#define POLY_REG_KEY_3            0x10C
#define POLY_REG_KEY_4            0x110
#define POLY_REG_KEY_5            0x114
#define POLY_REG_KEY_6            0x118
#define POLY_REG_KEY_7            0x11C
#define POLY_REG_BLOCK_0          0x120
#define POLY_REG_BLOCK_1          0x124
#define POLY_REG_BLOCK_2          0x128
#define POLY_REG_BLOCK_3          0x12C
#define POLY_REG_BLOCK_LEN        0x130
#define POLY_REG_MAC_0            0x134
#define POLY_REG_MAC_1            0x138
#define POLY_REG_MAC_2            0x13C
#define POLY_REG_MAC_3            0x140
#define POLY_REG_INIT             0x144
#define POLY_REG_NEXT             0x148
#define POLY_REG_FINISH           0x14C
#define POLY_REG_RESET_N          0x150
#define POLY_REG_READY            0x154



#define REG32(p, i)	((p)[(i) >> 2])
#define _REG64(p, i) (*(volatile uint64_t *)((p) + (i)))
#define _REG32(p, i) (*(volatile uint32_t *)((p) + (i)))
#define _REG16(p, i) (*(volatile uint16_t *)((p) + (i)))


#define POLY_CTRL_ADDR _AC(0x64007000,UL)
#define POLY_CTRL_SIZE _AC(0x1000,UL)
static volatile uint64_t * const poly = (void *)(POLY_CTRL_ADDR);
extern uintptr_t poly_reg;

void hwpoly1305_init(void* polyctrl, uint32_t key[8]);
void hwpoly1305_next(void* polyctrl, uint32_t block [4], int block_len);
void hwpoly1305_finish(void* polyctrl);
void hwpoly1305_results(void* polyctrl);
void hwpoly1305_debug(void* polyctrl);
void hwpoly1305_selftest(void* polyctrl);

/* SOFTWARE */
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

// figure out how many n byte blocks
// will fit in length x
#define align16(x) (x & ~15)
#define align64(x) (x & ~63)

// one u32 into 4x u8; (x: u32, y: u8 *)

#define u32_u8le(x, y)        \
                              \
    y[0] = x         & 0xff;  \
    y[1] = (x >> 8)  & 0xff;  \
    y[2] = (x >> 16) & 0xff;  \
    y[3] = (x >> 24) & 0xff;  \
                            



// 4x u8 into one u32
#define u8_u32le(x)         \
(                           \
    ((u32) x[0]        |    \
    ((u32) x[1] << 8)  |    \
    ((u32) x[2] << 16) |    \
    ((u32) x[3] << 24) )    \
)                           \

// rotate x left by n bits
#define rotl(x, n) ((x << n) | (x >> (-n & 31)))


// generate 128 bit tag using 256 bit key
void poly1305_tag( const uint8_t key[32], const uint8_t *data, const uint32_t len, uint8_t *tag);
void poly1305_state(uint32_t r[4], uint32_t s[4], const uint8_t key[32]);
void poly_final(uint32_t accum[5],uint32_t s[5], uint8_t *output);