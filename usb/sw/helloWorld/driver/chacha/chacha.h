#include <stdint.h>
#include "include/platform.h"
#include "kprintf.h"
#include <string.h>


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