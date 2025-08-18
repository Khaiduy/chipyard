#ifndef _DRIVERS_TRNG_H
#define _DRIVERS_TRNG_H


#ifndef __ASSEMBLER__

#define MAX_WAIT_TIME 1000000
#define TRNG_ERROR_WAIT -1
#define TRNG_ERROR_RANDOM -2
#define TRNG_OKAY 0

// #include <stdint.h>
// #include "user_settings.h"

#include <stdint.h>
#include "include/platform.h"

// #ifdef CUSTOM_LIBECC
//     #include "libecc_utils/libecc_utils.h"
// #endif //CUSTOM_LIBECC

#define REG32(p, i)	((p)[(i) >> 2])
#define _REG64(p, i) (*(volatile uint64_t *)((p) + (i)))
#define _REG32(p, i) (*(volatile uint32_t *)((p) + (i)))
#define _REG16(p, i) (*(volatile uint16_t *)((p) + (i)))


#define TRNG_CTRL_ADDR _AC(0x64005000,UL)
#define TRNG_CTRL_SIZE _AC(0x1000,UL)
static volatile uint64_t * const trng = (void *)(TRNG_CTRL_ADDR);
extern uintptr_t trng_reg;

void trng_reset(void* trngctrl);
void trng_reset_disable(void* trngctrl);

int trng_setup(void* trngctrl, uint32_t delay);
uint32_t trng_get_random(void* trngctrl);



#endif /* !__ASSEMBLER__ */

#endif /* _DRIVERS_TRNG_H */
