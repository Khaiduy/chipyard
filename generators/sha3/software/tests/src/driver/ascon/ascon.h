// See LICENSE for license details.
#include <stdint.h>
#include "include/platform.h"
//#include "kprintf.h"
#include <string.h>

#define _REG64(p, i) (*(volatile uint64_t *)((p) + (i)))
#define _REG32(p, i) (*(volatile uint32_t *)((p) + (i))) // Deprecated for 64-bit interface
#define _REG16(p, i) (*(volatile uint16_t *)((p) + (i)))

#ifndef _ASCON_DEV_H
#define _ASCON_DEV_H

/* Register offsets for 64-bit CPU interface */

#define IRESETN                 0x100
#define config_in               0x108

#define input_fifo_wr_en        0x110
#define input_fifo_wr_data      0x118
#define output_fifo_rd_data     0x120
// #define output_fifo_rd_valid    0x128
#define output_fifo_rd_en       0x128
#define key_in_0                0x130
#define key_in_1                0x138
#define key_wr_en               0x140
#define nonce_in_0              0x148
#define nonce_in_1              0x150
#define nonce_wr_en             0x158
#define status_out              0x160
#define tag_out_0               0x168
#define tag_out_1               0x170
#define tag_out_2               0x178
#define tag_out_3               0x180


/* Function declarations */

/* Basic hardware control */
void hw_ascon_reset(void* ascon_ctrl);
uint64_t hw_ascon_get_status(void* ascon_ctrl);
int hw_ascon_is_busy(void* ascon_ctrl);
int hw_ascon_is_done(void* ascon_ctrl);
int hw_ascon_is_tag_valid(void* ascon_ctrl);

/* HMAC operations */
void hw_ascon_hmac(void* ascon_ctrl, 
                   const uint8_t* key, size_t key_len,
                   const uint8_t* message, size_t msg_len,
                   uint64_t* tag);

/* HKDF operations (using HMAC-Ascon) */
void hw_ascon_hkdf_extract(void* ascon_ctrl,
                            const uint8_t* salt, size_t salt_len,
                            const uint8_t* ikm, size_t ikm_len,
                            uint64_t* prk);

void hw_ascon_hkdf_expand(void* ascon_ctrl,
                          const uint8_t* prk, size_t prk_len,
                          const uint8_t* info, size_t info_len,
                          uint8_t* okm, size_t okm_len);

/* HASH operations */
void hw_ascon_hash(void* ascon_ctrl,
                   const uint8_t* message, size_t msg_len,
                   uint64_t* tag);

/* AEAD operations */
void hw_ascon_aead(void* ascon_ctrl,
                   const uint8_t* key,
                   const uint8_t* nonce,
                   const uint8_t* ad, size_t ad_len,
                   const uint8_t* input, size_t in_len,
                   uint8_t* output,
                   uint64_t* tag,
                   int mode);

/* CXOF operations */
void hw_ascon_cxof(void* ascon_ctrl,
                   const uint8_t* custom, size_t custom_len,
                   const uint8_t* message, size_t msg_len,
                   uint8_t* output, size_t output_len);

/* Test suite */
void hw_ascon_run_all_tests(void* ascon_ctrl);

#endif /* _ASCON_DEV_H */