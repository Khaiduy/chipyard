#include <stdint.h>
#include "include/platform.h"
#include "kprintf.h"
#include <string.h>


#define REG32(p, i)	((p)[(i) >> 2])
#define _REG64(p, i) (*(volatile uint64_t *)((p) + (i)))
#define _REG32(p, i) (*(volatile uint32_t *)((p) + (i)))
#define _REG16(p, i) (*(volatile uint16_t *)((p) + (i)))


#define AES_CTRL_ADDR _AC(0x64009000,UL)
#define AES_CTRL_SIZE _AC(0x1000,UL)
static volatile uint64_t * const aes = (void *)(AES_CTRL_ADDR);
extern uintptr_t aes_reg;

void hwaes_reset(void* aesctrl);

void hwaes_selftest(void* aesctrl);