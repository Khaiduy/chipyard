// See LICENSE for license details.
#include <stdint.h>
#include "include/platform.h"
//#include "kprintf.h"
#include <string.h>

#define _REG64(p, i) (*(volatile uint64_t *)((p) + (i)))
#define _REG32(p, i) (*(volatile uint32_t *)((p) + (i))) // Deprecated for 64-bit interface
#define _REG16(p, i) (*(volatile uint16_t *)((p) + (i)))

#ifndef _AES_GCM_DEV_H
#define _AES_GCM_DEV_H

/* Register offsets for 64-bit CPU interface */
#define AES_GCM_REG_ICTRL        0x100
#define AES_GCM_REG_OREADY       0x108

#define AES_GCM_REG_IIV_0        0x110
#define AES_GCM_REG_IIV_1        0x118
#define AES_GCM_REG_IIV_VALID    0x120

#define AES_GCM_REG_IKEY_0       0x128
#define AES_GCM_REG_IKEY_1       0x130
#define AES_GCM_REG_IKEY_2       0x138
#define AES_GCM_REG_IKEY_3       0x140
#define AES_GCM_REG_IKEY_VALID   0x148
#define AES_GCM_REG_IKEYLEN      0x150

#define AES_GCM_REG_IAAD_0       0x158
#define AES_GCM_REG_IAAD_1       0x160
#define AES_GCM_REG_IAAD_VALID   0x168

#define AES_GCM_REG_IBLOCK_0     0x170
#define AES_GCM_REG_IBLOCK_1     0x178
#define AES_GCM_REG_IBLOCK_VALID 0x180

#define AES_GCM_REG_ITAG_0       0x188
#define AES_GCM_REG_ITAG_1       0x190
#define AES_GCM_REG_ITAG_VALID   0x198

#define AES_GCM_REG_ORESULT_0    0x1A0
#define AES_GCM_REG_ORESULT_1    0x1A8
#define AES_GCM_REG_ORESULT_VALID 0x1B0

#define AES_GCM_REG_OTAG_0       0x1B8
#define AES_GCM_REG_OTAG_1       0x1C0
#define AES_GCM_REG_OTAG_VALID   0x1C8

#define AES_GCM_REG_OAUTHENTIC   0x1D0
#define AES_GCM_REG_IRESETN      0x1D8

#define AES_GCM_REG_IBLOCK_BYTES  0x1E0

#endif /* _AES_GCM_DEV_H */