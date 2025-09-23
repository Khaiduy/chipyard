#include <stdint.h>
#include "include/platform.h"
//#include "kprintf.h"
#include <string.h>

/* Register offsets */
#define CHACHA_REG_KEY_0            0x100
#define CHACHA_REG_KEY_1            0x104
#define CHACHA_REG_KEY_2            0x108
#define CHACHA_REG_KEY_3            0x10C
#define CHACHA_REG_KEY_4            0x110
#define CHACHA_REG_KEY_5            0x114
#define CHACHA_REG_KEY_6            0x118
#define CHACHA_REG_KEY_7            0x11C
#define CHACHA_REG_NONCE_0          0x120
#define CHACHA_REG_NONCE_1          0x124
#define CHACHA_REG_NONCE_2          0x128
#define CHACHA_REG_B_COUNTER        0x12C
#define CHACHA_REG_IN_0             0x130
#define CHACHA_REG_IN_1             0x134
#define CHACHA_REG_IN_2             0x138
#define CHACHA_REG_IN_3             0x13C
#define CHACHA_REG_IN_4             0x140
#define CHACHA_REG_IN_5             0x144
#define CHACHA_REG_IN_6             0x148
#define CHACHA_REG_IN_7             0x14C
#define CHACHA_REG_IN_8             0x150
#define CHACHA_REG_IN_9             0x154
#define CHACHA_REG_IN_10            0x158
#define CHACHA_REG_IN_11            0x15C
#define CHACHA_REG_IN_12            0x160
#define CHACHA_REG_IN_13            0x164
#define CHACHA_REG_IN_14            0x168
#define CHACHA_REG_IN_15            0x16C
#define CHACHA_REG_RST_CORE         0x170
#define CHACHA_REG_INIT             0x174
#define CHACHA_REG_NEXT             0x178
#define CHACHA_REG_READY            0x17C
#define CHACHA_REG_OUT_0            0x180
#define CHACHA_REG_OUT_1            0x184
#define CHACHA_REG_OUT_2            0x188
#define CHACHA_REG_OUT_3            0x18C
#define CHACHA_REG_OUT_4            0x190
#define CHACHA_REG_OUT_5            0x194
#define CHACHA_REG_OUT_6            0x198
#define CHACHA_REG_OUT_7            0x19C
#define CHACHA_REG_OUT_8            0x200
#define CHACHA_REG_OUT_9            0x204
#define CHACHA_REG_OUT_10           0x208
#define CHACHA_REG_OUT_11           0x20C
#define CHACHA_REG_OUT_12           0x210
#define CHACHA_REG_OUT_13           0x214
#define CHACHA_REG_OUT_14           0x218
#define CHACHA_REG_OUT_15           0x21C


#define REG32(p, i)	((p)[(i) >> 2])
#define _REG64(p, i) (*(volatile uint64_t *)((p) + (i)))
#define _REG32(p, i) (*(volatile uint32_t *)((p) + (i)))
#define _REG16(p, i) (*(volatile uint16_t *)((p) + (i)))


#define CHACHA_CTRL_ADDR _AC(0x64006000,UL)
#define CHACH_CTRL_SIZE _AC(0x1000,UL)
static volatile uint64_t * const chacha = (void *)(CHACHA_CTRL_ADDR);
extern uintptr_t chacha_reg;


void hwchacha_init(void* chachactrl);

void hwchacha_next(void* chachactrl);

void hwchacha20_init(void* chachactrl, uint32_t key[8], uint32_t nonce[3],uint32_t counter, uint32_t plain_text [16]);

void hwchacha20_next(void* chachactrl, uint32_t plain_text [16]);

void hwchacha20_results(void* chachactrl);

void hwchacha20_selftest(void* chachactrl);


/* SOFTWARE */
void ChaCha20XOR(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *input, uint8_t *output, int inputlen);