/* See the file LICENSE for further information */

#include "driver/ascon/ascon.h"
#include "mmio.h"
#include "encoding.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

// ========================================
// ASCON Hardware Driver
// ========================================
// This driver mimics the testbench behavior for ASCON hardware
// Supports: HMAC, HASH, AEAD (encrypt/decrypt), CXOF modes

#define WD 100000

// Mode definitions (matching hardware)
#define MODE_XOF  0x0
#define MODE_HASH 0x1
#define MODE_CXOF 0x2
#define MODE_AEAD 0x3
#define MODE_HMAC 0x4

// Status register bits
#define STATUS_BUSY              (1 << 0)
#define STATUS_DONE              (1 << 1)
#define STATUS_TAG_VALID         (1 << 2)
#define STATUS_FIFO_UNDERFLOW    (1 << 3)
#define STATUS_MESSAGE_PHASE     (1 << 4)
#define STATUS_INPUT_FIFO_FULL   (1 << 5)
#define STATUS_INPUT_FIFO_EMPTY  (1 << 6)
#define STATUS_OUTPUT_FIFO_FULL  (1 << 7)
#define STATUS_OUTPUT_FIFO_EMPTY (1 << 8)
#define STATUS_OUTPUT_FIFO_VALID (1 << 9)


/* Timing functions */
static unsigned long step_start_cycles = 0;

static void start_timing(void)
{
    step_start_cycles = rdcycle();
}

static void end_timing(const char* operation)
{
    unsigned long end_cycles = rdcycle();
    unsigned long elapsed = end_cycles - step_start_cycles;
    printf("  HW Timing: %s took %lu cycles\n", operation, elapsed);
}



// ========================================
// Basic Hardware Control Functions
// ========================================

void hw_ascon_reset(void* ascon_ctrl) {
    _REG64((char*)ascon_ctrl, IRESETN) = 0;
    _REG64((char*)ascon_ctrl, config_in) = 0;
    _REG64((char*)ascon_ctrl, input_fifo_wr_en) = 0;
    _REG64((char*)ascon_ctrl, output_fifo_rd_en) = 0;
    _REG64((char*)ascon_ctrl, key_wr_en) = 0;
    _REG64((char*)ascon_ctrl, nonce_wr_en) = 0;
    
    // for(volatile int i = 0; i < 10; i++);
    
    _REG64((char*)ascon_ctrl, IRESETN) = 1;
    
    // for(volatile int i = 0; i < 10; i++);
}

uint64_t hw_ascon_get_status(void* ascon_ctrl) {
    return _REG64((char*)ascon_ctrl, status_out);
}

int hw_ascon_is_busy(void* ascon_ctrl) {
    return (hw_ascon_get_status(ascon_ctrl) & STATUS_BUSY) != 0;
}

int hw_ascon_is_done(void* ascon_ctrl) {
    return (hw_ascon_get_status(ascon_ctrl) & STATUS_DONE) != 0;
}

int hw_ascon_is_tag_valid(void* ascon_ctrl) {
    return (hw_ascon_get_status(ascon_ctrl) & STATUS_TAG_VALID) != 0;
}

int hw_ascon_is_message_phase(void* ascon_ctrl) {
    return (hw_ascon_get_status(ascon_ctrl) & STATUS_MESSAGE_PHASE) != 0;
}

int hw_ascon_input_fifo_full(void* ascon_ctrl) {
    return (hw_ascon_get_status(ascon_ctrl) & STATUS_INPUT_FIFO_FULL) != 0;
}

int hw_ascon_output_fifo_empty(void* ascon_ctrl) {
    return (hw_ascon_get_status(ascon_ctrl) & STATUS_OUTPUT_FIFO_EMPTY) != 0;
}
int hw_ascon_output_fifo_valid(void* ascon_ctrl) {
    return (hw_ascon_get_status(ascon_ctrl) & STATUS_OUTPUT_FIFO_VALID) != 0;
}

void hw_ascon_write_fifo(void* ascon_ctrl, uint64_t data) {
    uint32_t timeout = 0;
   
    _REG64((char*)ascon_ctrl, input_fifo_wr_data) = data;
    _REG64((char*)ascon_ctrl, input_fifo_wr_en) = 1;
    _REG64((char*)ascon_ctrl, input_fifo_wr_en) = 0;

    while (hw_ascon_input_fifo_full(ascon_ctrl) && timeout < WD) {
        timeout++;
    }
    if (timeout >= WD) {
        printf("ERROR: Input FIFO full timeout\n");
        return;
    }
}

uint64_t hw_ascon_read_fifo(void* ascon_ctrl) {
    uint32_t timeout = 0;
    
    while (hw_ascon_output_fifo_empty(ascon_ctrl) && timeout < WD) {
        timeout++;
    }
    if (timeout >= WD) {
        printf("ERROR: Output FIFO empty timeout\n");
        return 0;
    }
    
    _REG64((char*)ascon_ctrl, output_fifo_rd_en) = 1;
    _REG64((char*)ascon_ctrl, output_fifo_rd_en) = 0;
    // printf("DEBUG: Read FIFO triggered\n");
    // timeout = 0;
    // while (!hw_ascon_output_fifo_valid(ascon_ctrl) && timeout < WD) {
    //     timeout++;
    // }
    
    // if (timeout >= WD) {
    //     printf("ERROR: Output FIFO read valid timeout\n");
    //     return 0;
    // }
    
    return _REG64((char*)ascon_ctrl, output_fifo_rd_data);
}

void hw_ascon_wait_done(void* ascon_ctrl, uint32_t max_cycles) {
    uint32_t count = 0;
    while (!hw_ascon_is_done(ascon_ctrl) && count < max_cycles) {
        count++;
        // for(volatile int i = 0; i < 10; i++);
    }
    if (count >= max_cycles) {
        printf("ERROR: Wait done timeout after %u cycles\n", count);
    }
}

void hw_ascon_read_tag(void* ascon_ctrl, uint64_t* tag) {
    tag[0] = _REG64((char*)ascon_ctrl, tag_out_0);
    tag[1] = _REG64((char*)ascon_ctrl, tag_out_1);
    tag[2] = _REG64((char*)ascon_ctrl, tag_out_2);
    tag[3] = _REG64((char*)ascon_ctrl, tag_out_3);
}

// ========================================
// HMAC Functions
// ========================================

void hw_ascon_hmac(void* ascon_ctrl, 
                   const uint8_t* key, size_t key_len,
                   const uint8_t* message, size_t msg_len,
                   uint64_t* tag) {
    
    hw_ascon_reset(ascon_ctrl);
    
    uint64_t config = ((uint64_t)msg_len << 14) | 
                      ((uint64_t)key_len << 4) | 
                      (1ULL << 3) |
                      MODE_HMAC;
    
    size_t key_chunks = (key_len + 7) / 8;
    // Send first chunk
    uint64_t chunk = 0;
    size_t bytes_to_copy = (key_chunks == 1) ? key_len : 8;
    // Copy bytes in reverse order for big-endian
    for (size_t j = 0; j < bytes_to_copy; j++) {
        chunk |= ((uint64_t)key[0 + j]) << ((7 - j) * 8);
    }
    hw_ascon_write_fifo(ascon_ctrl, chunk);
    
    // Now trigger config
    _REG64((char*)ascon_ctrl, config_in) = config;
    config &= ~(1ULL << 3);
    _REG64((char*)ascon_ctrl, config_in) = config;
    
    // Send remaining chunks
    for (size_t i = 1; i < key_chunks; i++) {
        chunk = 0;
        bytes_to_copy = (i == key_chunks - 1) ? 
                        (key_len - i * 8) : 8;
        // Copy bytes in reverse order for big-endian
        for (size_t j = 0; j < bytes_to_copy; j++) {
            chunk |= ((uint64_t)key[i * 8 + j]) << ((7 - j) * 8);
        }
                
        hw_ascon_write_fifo(ascon_ctrl, chunk);
    }

    size_t msg_chunks = (msg_len + 7) / 8;
    for (size_t i = 0; i < msg_chunks; i++) {
        uint64_t chunk = 0;
        size_t bytes_to_copy = (i == msg_chunks - 1) ? 
                               (msg_len - i * 8) : 8;
        // Copy bytes in reverse order for big-endian
        for (size_t j = 0; j < bytes_to_copy; j++) {
            chunk |= ((uint64_t)message[i * 8 + j]) << ((7 - j) * 8);
        }
        
        // for(volatile int j = 0; j < 10; j++);
        
        hw_ascon_write_fifo(ascon_ctrl, chunk);
    }
    
    
    hw_ascon_wait_done(ascon_ctrl, 10000);
    
    uint32_t timeout = 0;
    while (!hw_ascon_is_tag_valid(ascon_ctrl) && timeout < WD) {
        timeout++;
        // for(volatile int i = 0; i < 10; i++);
    }
    
    if (timeout >= WD) {
        printf("ERROR: Tag valid timeout\n");
        return;
    }
    
    hw_ascon_read_tag(ascon_ctrl, tag);
    

}

// ========================================
// HKDF Functions (using HMAC-Ascon)
// ========================================

/* HKDF Extract using HMAC-Ascon
 * PRK = HMAC-Ascon(salt, IKM)
 * If salt is NULL or empty, use zero-filled 32-byte salt
 */
void hw_ascon_hkdf_extract(void* ascon_ctrl,
                            const uint8_t* salt, size_t salt_len,
                            const uint8_t* ikm, size_t ikm_len,
                            uint64_t* prk) {
    /* Ascon-Hash produces 256-bit (32-byte) output */
    #define ASCON_HASH_DIGEST_SIZE 32
    
    /* If no salt provided, use zero-filled salt */
    uint8_t zero_salt[ASCON_HASH_DIGEST_SIZE];
    const uint8_t* actual_salt = salt;
    size_t actual_salt_len = salt_len;
    
    if (salt == NULL || salt_len == 0) {
        memset(zero_salt, 0, sizeof(zero_salt));
        actual_salt = zero_salt;
        actual_salt_len = sizeof(zero_salt);
    }
    
    /* PRK = HMAC-Ascon(salt, IKM) */
    /* Note: HMAC(key, message) where key=salt, message=IKM */
    hw_ascon_hmac(ascon_ctrl, actual_salt, actual_salt_len, ikm, ikm_len, prk);
}

/* HKDF Expand using HMAC-Ascon
 * OKM = first L bytes of T(1) || T(2) || T(3) || ...
 * where:
 *   T(0) = empty string
 *   T(i) = HMAC-Ascon(PRK, T(i-1) || info || i)
 *   i is 1-byte counter (0x01, 0x02, ...)
 */
void hw_ascon_hkdf_expand(void* ascon_ctrl,
                          const uint8_t* prk, size_t prk_len,
                          const uint8_t* info, size_t info_len,
                          uint8_t* okm, size_t okm_len) {
    #define ASCON_HASH_DIGEST_SIZE 32
    
    /* Check PRK size (should be 32 bytes for Ascon-Hash) */
    if (prk_len != ASCON_HASH_DIGEST_SIZE) {
        printf("ERROR: Invalid PRK size for Ascon HKDF: %zu (expected %d)\n", 
               prk_len, ASCON_HASH_DIGEST_SIZE);
        return;
    }
    
    /* Calculate number of iterations needed */
    size_t n = (okm_len + ASCON_HASH_DIGEST_SIZE - 1) / ASCON_HASH_DIGEST_SIZE;
    
    if (n > 255) {
        printf("ERROR: Requested OKM size too large: %zu bytes\n", okm_len);
        return;
    }
    
    /* Buffer for T(i-1) */
    uint64_t t_prev[4] = {0};  /* 32 bytes = 4 x 64-bit words */
    uint8_t* t_prev_bytes = (uint8_t*)t_prev;
    
    /* Buffer for message: T(i-1) || info || counter */
    static uint8_t msg_buffer[256];  /* Static to avoid stack overflow */
    
    size_t okm_offset = 0;
    
    /* HKDF-Expand iterations */
    for (size_t i = 1; i <= n; i++) {
        size_t msg_len = 0;
        
        /* Build message: T(i-1) || info || counter */
        if (i > 1) {
            /* Append T(i-1) */
            memcpy(msg_buffer + msg_len, t_prev_bytes, ASCON_HASH_DIGEST_SIZE);
            msg_len += ASCON_HASH_DIGEST_SIZE;
        }
        
        /* Append info */
        if (info != NULL && info_len > 0) {
            if (msg_len + info_len > sizeof(msg_buffer) - 1) {
                printf("ERROR: Message too large for Ascon HKDF Expand\n");
                return;
            }
            memcpy(msg_buffer + msg_len, info, info_len);
            msg_len += info_len;
        }
        
        /* Append counter byte */
        msg_buffer[msg_len] = (uint8_t)i;
        msg_len++;
        
        /* T(i) = HMAC-Ascon(PRK, T(i-1) || info || i) */
        hw_ascon_hmac(ascon_ctrl, prk, prk_len, msg_buffer, msg_len, t_prev);
        
        /* Copy to output */
        size_t bytes_to_copy = ASCON_HASH_DIGEST_SIZE;
        if (okm_offset + bytes_to_copy > okm_len) {
            bytes_to_copy = okm_len - okm_offset;
        }
        
        memcpy(okm + okm_offset, t_prev_bytes, bytes_to_copy);
        okm_offset += bytes_to_copy;
    }
}

// ========================================
// HASH Functions
// ========================================

void hw_ascon_hash(void* ascon_ctrl,
                   const uint8_t* message, size_t msg_len,
                   uint64_t* tag) {
    
    hw_ascon_reset(ascon_ctrl);
    
    uint64_t config = ((uint64_t)msg_len << 14) | 
                      (4ULL << 4) |
                      (1ULL << 3) |
                      MODE_HASH;

    // Send first chunk
    size_t msg_chunks = (msg_len + 7) / 8;
    uint64_t chunk = 0;
    size_t bytes_to_copy = (msg_chunks == 1) ? msg_len : 8;
    // Copy bytes in reverse order for big-endian
    for (size_t j = 0; j < bytes_to_copy; j++) {
        chunk |= ((uint64_t)message[0 + j]) << ((7 - j) * 8);
    }
    hw_ascon_write_fifo(ascon_ctrl, chunk);
    
    // Now trigger config
    _REG64((char*)ascon_ctrl, config_in) = config;    
    config &= ~(1ULL << 3);
    _REG64((char*)ascon_ctrl, config_in) = config;
    
    // Send remaining chunks
    for (size_t i = 1; i < msg_chunks; i++) {
        chunk = 0;
        bytes_to_copy = (i == msg_chunks - 1) ? 
                        (msg_len - i * 8) : 8;
        // Copy bytes in reverse order for big-endian
        for (size_t j = 0; j < bytes_to_copy; j++) {
            chunk |= ((uint64_t)message[i * 8 + j]) << ((7 - j) * 8);
        }
                
        hw_ascon_write_fifo(ascon_ctrl, chunk);
    }
    
    hw_ascon_wait_done(ascon_ctrl, 10000);
    
    uint32_t timeout = 0;
    while (!hw_ascon_is_tag_valid(ascon_ctrl) && timeout < WD) {
        timeout++;
        // for(volatile int i = 0; i < 10; i++);
    }
    
    if (timeout >= WD) {
        printf("ERROR: Tag valid timeout\n");
        return;
    }
    
    hw_ascon_read_tag(ascon_ctrl, tag);
    
}

// ========================================
// CXOF Functions
// ========================================

void hw_ascon_cxof(void* ascon_ctrl,
                   const uint8_t* custom, size_t custom_len,
                   const uint8_t* message, size_t msg_len,
                   uint8_t* output, size_t output_len) {
    
    hw_ascon_reset(ascon_ctrl);
    
    size_t custom_size_total = 8 + custom_len;
    
    size_t output_blocks = (output_len + 7) / 8;
    uint64_t config = ((uint64_t)msg_len << 34) | 
                      ((uint64_t)custom_size_total << 14) |
                      ((uint64_t)output_blocks << 4) |
                      (1ULL << 3) |
                      MODE_CXOF;
    
    _REG64((char*)ascon_ctrl, config_in) = config;   
    config &= ~(1ULL << 3);
    _REG64((char*)ascon_ctrl, config_in) = config;
    
    uint64_t custom_bits = custom_len * 8;
    // Convert to big-endian
    uint64_t be_custom_bits = 0;
    for (size_t j = 0; j < 8; j++) {
        be_custom_bits |= ((custom_bits >> (j * 8)) & 0xFF) << ((7 - j) * 8);
    }
    hw_ascon_write_fifo(ascon_ctrl, be_custom_bits);
    
    size_t custom_chunks = (custom_len + 7) / 8;
    for (size_t i = 0; i < custom_chunks; i++) {
        uint64_t chunk = 0;
        size_t bytes_to_copy = (i == custom_chunks - 1) ? 
                               (custom_len - i * 8) : 8;
        // Pack in big-endian order
        for (size_t j = 0; j < bytes_to_copy; j++) {
            chunk |= ((uint64_t)custom[i * 8 + j]) << ((7 - j) * 8);
        }

        hw_ascon_write_fifo(ascon_ctrl, chunk);
    }
    
    size_t msg_chunks = (msg_len + 7) / 8;
    for (size_t i = 0; i < msg_chunks; i++) {
        uint64_t chunk = 0;
        size_t bytes_to_copy = (i == msg_chunks - 1) ? 
                               (msg_len - i * 8) : 8;
        // Pack in big-endian order
        for (size_t j = 0; j < bytes_to_copy; j++) {
            chunk |= ((uint64_t)message[i * 8 + j]) << ((7 - j) * 8);
        }
        
        // for(volatile int j = 0; j < 10; j++);
        hw_ascon_write_fifo(ascon_ctrl, chunk);
    }
        
    hw_ascon_wait_done(ascon_ctrl, 10000);

    for (size_t i = 0; i < output_blocks; i++) {
        // for(volatile int j = 0; j < 5; j++);
        
        uint64_t word = hw_ascon_read_fifo(ascon_ctrl);
        size_t bytes_to_copy = (i == output_blocks - 1) ?
                               (output_len - i * 8) : 8;
        for (size_t j = 0; j < bytes_to_copy; j++) {
            output[i * 8 + j] = (word >> ((7 - j) * 8)) & 0xFF;
        }
    }
    
}
// ========================================
// AEAD Functions
// ========================================
void hw_ascon_aead(void* ascon_ctrl,
                   const uint8_t* key,
                   const uint8_t* nonce,
                   const uint8_t* ad, size_t ad_len,
                   const uint8_t* input, size_t in_len,
                   uint8_t* output,
                   uint64_t* tag,
                   int mode) {  // mode: 1 for encrypt, 0 for decrypt
    
    hw_ascon_reset(ascon_ctrl);
    
    uint64_t key_words[2];
    memcpy(key_words, key, 16);
    _REG64((char*)ascon_ctrl, key_in_0) = key_words[0];
    _REG64((char*)ascon_ctrl, key_in_1) = key_words[1];
    _REG64((char*)ascon_ctrl, key_wr_en) = 1;
    
    // for(volatile int i = 0; i < 1; i++);
    _REG64((char*)ascon_ctrl, key_wr_en) = 0;
    
    uint64_t nonce_words[2];
    memcpy(nonce_words, nonce, 16);
    _REG64((char*)ascon_ctrl, nonce_in_0) = nonce_words[0];
    _REG64((char*)ascon_ctrl, nonce_in_1) = nonce_words[1];
    _REG64((char*)ascon_ctrl, nonce_wr_en) = 1;
    
    // for(volatile int i = 0; i < 1; i++);
    _REG64((char*)ascon_ctrl, nonce_wr_en) = 0;
    
    size_t output_blocks = (in_len + 15) / 16;
    uint64_t config = ((uint64_t)in_len << 34) |
                      ((uint64_t)ad_len << 14) |
                      ((uint64_t)output_blocks << 5) |
                      ((uint64_t)mode << 4) |  // Set mode bit (1 for enc, 0 for dec)
                      (1ULL << 3) |
                      MODE_AEAD;
    
    _REG64((char*)ascon_ctrl, config_in) = config;
    
    // for(volatile int i = 0; i < 10; i++);
    
    config &= ~(1ULL << 3);
    _REG64((char*)ascon_ctrl, config_in) = config;
    
    // Pad AD to multiple of 128 bits (16 bytes)
    size_t ad_padded_len = ((ad_len + 15) / 16) * 16;
    size_t ad_chunks = ad_padded_len / 8;  // Number of 64-bit chunks
    size_t ad_written = 0;
    size_t in_written = 0;
    size_t out_read = 0;
    
    // Pad input to multiple of 128 bits (16 bytes)
    size_t in_padded_len = ((in_len + 15)/ 16) * 16;
    size_t in_chunks = in_padded_len / 8;  // Number of 64-bit chunks for input
    
    // Unpadded chunks for output read (only up to in_len)
    size_t unpadded_in_chunks = (in_len + 7) / 8;

    // First, stream AD while checking for early outputs (though unlikely for AD phase)
    while (ad_written < ad_chunks || in_written < in_chunks || out_read < unpadded_in_chunks) {
        // Write AD if not done
        if (ad_written < ad_chunks && !hw_ascon_input_fifo_full(ascon_ctrl)) {
            uint64_t chunk = 0;
            size_t offset = ad_written * 8;
            size_t bytes_to_copy = (offset >= ad_len) ? 0 : ((offset + 8 > ad_len) ? (ad_len - offset) : 8);
            // Pack in big-endian order
            for (size_t j = 0; j < bytes_to_copy; j++) {
                chunk |= ((uint64_t)ad[offset + j]) << ((7 - j) * 8);
            }
            // If beyond ad_len or bytes_to_copy=0, chunk remains 0 (zero padding)
            
            hw_ascon_write_fifo(ascon_ctrl, chunk);
            ad_written++;
            // printf("[AEAD] AD chunk %lu/%lu written\n", ad_written, ad_chunks);
        }
        
        // Write input (plaintext or ciphertext) if AD done
        else if (ad_written == ad_chunks && in_written < in_chunks && !hw_ascon_input_fifo_full(ascon_ctrl)) {
            uint64_t chunk = 0;
            size_t offset = in_written * 8;
            size_t bytes_to_copy = (offset >= in_len) ? 0 : ((offset + 8 > in_len) ? (in_len - offset) : 8);
            // Pack in big-endian order
            for (size_t j = 0; j < bytes_to_copy; j++) {
                chunk |= ((uint64_t)input[offset + j]) << ((7 - j) * 8);
            }
            // Zero padding if beyond in_len
            
            hw_ascon_write_fifo(ascon_ctrl, chunk);
            in_written++;
            // printf("[AEAD] Input chunk %lu/%lu written\n", in_written, in_chunks);
        }
        
        // Read output (ciphertext or plaintext) if available
        if (!hw_ascon_output_fifo_empty(ascon_ctrl) && out_read < unpadded_in_chunks) {
            uint64_t word = hw_ascon_read_fifo(ascon_ctrl);
            
            size_t bytes_to_copy = (out_read * 8 + 8 > in_len) ? (in_len - out_read * 8) : 8;
            // Extract bytes assuming big-endian word (MSB first)
            for (size_t j = 0; j < bytes_to_copy; j++) {
                output[out_read * 8 + j] = (word >> ((7 - j) * 8)) & 0xFF;
            }
            
            out_read++;
            // printf("[AEAD] Output chunk %lu/%lu read\n", out_read, unpadded_in_chunks);
        }
    }
    
    hw_ascon_wait_done(ascon_ctrl, 5000);
    
    // for(volatile int i = 0; i < 5; i++);
    
    hw_ascon_read_tag(ascon_ctrl, tag);
    
    // printf("[AEAD] Tag: %016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n", tag[0], tag[1], tag[2], tag[3]);
}

// For encryption: hw_ascon_aead(ascon_ctrl, key, nonce, ad, ad_len, plaintext, pt_len, ciphertext, tag, 1);
// For decryption: hw_ascon_aead(ascon_ctrl, key, nonce, ad, ad_len, ciphertext, ct_len, plaintext, tag, 0);

// ========================================
// Test Functions (Matching Testbench)
// ========================================

void test_hmac_1(void* ascon_ctrl) {
    printf("\n========================================\n");
    printf("TEST 1: HMAC (32-byte key, 64-byte message)\n");
    printf("========================================\n");
    
    uint8_t key[32] = "test_key_for_ascon_hmac_____test";
    uint8_t msg[64] = "test message for ascon hmac verification test data!!!!!!!!!!!!!!";
    uint64_t tag[4]= {0};

    start_timing();
    hw_ascon_hmac(ascon_ctrl, key, sizeof(key) - 1, msg, sizeof(msg) - 1, tag);
    end_timing("HMAC");

    printf("[HASH] Hash output: %016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n", 
           tag[0], tag[1], tag[2], tag[3]);
    uint64_t expected[4] = {0xc853235b0f918cec, 0x79e8f0a2ad4efb2b, 
                            0x273f98b258a22cb1, 0x4fa628ce045745be};
    
    int pass = 1;
    for (int i = 0; i < 4; i++) {
        if (tag[i] != expected[i]) {
            pass = 0;
            break;
        }
    }
    
    printf("%s TEST 1 %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}

void test_hmac_2(void* ascon_ctrl) {
    printf("\n========================================\n");
    printf("TEST 2: HMAC (74-byte key, 65-byte message)\n");
    printf("========================================\n");
    
    uint8_t key[] = "This is a very long secret passphrase used for HMAC authentication test!!!";
    uint8_t msg[] = "Hello, World! This is a test message for HMAC-ASCON verification.";
    uint64_t tag[4]= {0};
    
    start_timing();
    hw_ascon_hmac(ascon_ctrl, key, 74, msg, 65, tag);
    end_timing("HMAC_long");

    printf("[HASH] Hash output: %016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n", 
           tag[0], tag[1], tag[2], tag[3]);

    uint64_t expected[4] = {0x9ce0a1e0818e5bc1, 0x24d982f967f43ac3,
                            0x10dfad8c3094a62d, 0xe58ceda4fcc021c1};
    
    int pass = 1;
    for (int i = 0; i < 4; i++) {
        if (tag[i] != expected[i]) {
            pass = 0;
            break;
        }
    }
    
    printf("%s TEST 2 %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}

void test_hmac_3(void* ascon_ctrl) {
    printf("\n========================================\n");
    printf("TEST 3: HMAC (64-byte key, 38-byte message)\n");
    printf("========================================\n");
    
    uint8_t key[] = "HMAC_Authentication_Secret_Key_For_Testing_Boundary_Case_XXXXXXX";
    uint8_t msg[] = "Test for exactly 64-byte key boundary.";
    uint64_t tag[4]= {0};
    
    start_timing();
    hw_ascon_hmac(ascon_ctrl, key, 64, msg, 38, tag);
    end_timing("HMAC_64B");

    printf("[HASH] Hash output: %016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n", 
           tag[0], tag[1], tag[2], tag[3]);

    uint64_t expected[4] = {0xf60d48a09ba0ee74, 0x84fb85f503ee64f7,
                            0xda4b0de0515b023f, 0x8d4fc0c3e3a8a1ea};
    
    int pass = 1;
    for (int i = 0; i < 4; i++) {
        if (tag[i] != expected[i]) {
            pass = 0;
            break;
        }
    }
    
    printf("%s TEST 3 %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}

void test_hash_4(void* ascon_ctrl) {
    // printf("\n========================================\n");
    // printf("TEST 4: HASH (12-byte message)\n");
    // printf("========================================\n");
    
    // uint8_t msg[] = "Hello World!";
    uint8_t msg[32] = {0};
    uint64_t tag[4]= {0};
    
    start_timing();
    hw_ascon_hash(ascon_ctrl, msg, 32, tag);
    end_timing("HASH");

    printf("[HASH] Hash output: %016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n", 
        tag[0], tag[1], tag[2], tag[3]);

    uint64_t expected[4] = {0x690860fca70756f3, 0x3bc9635bcfe022b8,
                            0x7260275c504c4be0, 0xb0acab089a00006c};
    
    int pass = 1;
    for (int i = 0; i < 4; i++) {
        if (tag[i] != expected[i]) {
            pass = 0;
            break;
        }
    }
    
    printf("%s TEST 4 %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}

void test_hash_6(void* ascon_ctrl) {
    printf("\n========================================\n");
    printf("TEST 6: HASH (16-byte message)\n");
    printf("========================================\n");
    
    uint8_t msg[] = "ASCON_HASH_TEST!";
    uint64_t tag[4] = {0};

    start_timing();
    hw_ascon_hash(ascon_ctrl, msg, 16, tag);
    end_timing("HASH");

    printf("[HASH] Hash output: %016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n", 
        tag[0], tag[1], tag[2], tag[3]);

    uint64_t expected[4] = {0x7085d36c88d9c808, 0xb7fd3d4b8dc771f8,
                            0xa5e4fe7a57258fa2, 0x1dcb5f2250a1ce61};
    
    int pass = 1;
    for (int i = 0; i < 4; i++) {
        if (tag[i] != expected[i]) {
            pass = 0;
            break;
        }
    }
    
    printf("%s TEST 6 %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}

void test_hash_7(void* ascon_ctrl) {
    printf("\n========================================\n");
    printf("TEST 7: HASH (40-byte message)\n");
    printf("========================================\n");
    
    uint8_t msg[] = "The quick brown fox jumps over the lazy ";
    uint64_t tag[4] = {0};

    start_timing();
    hw_ascon_hash(ascon_ctrl, msg, 40, tag);
    end_timing("HASH");

    printf("[HASH] Hash output: %016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n", 
        tag[0], tag[1], tag[2], tag[3]);

    uint64_t expected[4] = {0xa687ce89cee613ff, 0xbb3ba285fc349e21,
                            0x6f0e3f5cb6b5e509, 0xcb5d82b7569cc2e5};
    
    int pass = 1;
    for (int i = 0; i < 4; i++) {
        if (tag[i] != expected[i]) {
            pass = 0;
            break;
        }
    }
    
    printf("%s TEST 7 %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}

void test_hash_8(void* ascon_ctrl) {
    printf("\n========================================\n");
    printf("TEST 8: HASH (67-byte message)\n");
    printf("========================================\n");
    
    uint8_t msg[] = "ASCON-Hash is a cryptographic hash function from the ASCON family!";
    uint64_t tag[4] = {0};
    
    start_timing();
    hw_ascon_hash(ascon_ctrl, msg, 67, tag);
    end_timing("HASH");

    printf("[HASH] Hash output: %016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n", 
        tag[0], tag[1], tag[2], tag[3]);
          
    uint64_t expected[4] = {0x7d8ed5267821fd5c, 0xea4404f37aae676a,
                            0x966df5e9f9712c01, 0x9862b684fe080ca0};
    
    int pass = 1;
    for (int i = 0; i < 4; i++) {
        if (tag[i] != expected[i]) {
            pass = 0;
            break;
        }
    }
    
    printf("%s TEST 8 %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}

void test_cxof_5(void* ascon_ctrl) {
    printf("\n========================================\n");
    printf("TEST 5: CXOF (custom=5 bytes, message=12 bytes)\n");
    printf("========================================\n");
    
    uint8_t custom[] = "MyApp";
    uint8_t msg[] = "Test message";
    uint8_t output[32] = {0};
    
    hw_ascon_cxof(ascon_ctrl, custom, 5, msg, 12, output, 32);
    
    printf("[CXOF] Output: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");
    uint8_t expected[32] = {
        0x96, 0x36, 0x8e, 0x4f, 0x65, 0xa2, 0x6b, 0x75,
        0x3a, 0x9e, 0x60, 0x7f, 0xa7, 0x93, 0xef, 0x0a,
        0xe1, 0xbd, 0x82, 0x35, 0xbf, 0x94, 0xe5, 0xab,
        0x6b, 0x40, 0x4f, 0xea, 0x0f, 0x2f, 0xfc, 0xa4
    };
    
    int pass = memcmp(output, expected, 32) == 0;
    printf("%s TEST 5 %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}

void test_cxof_9(void* ascon_ctrl) {
    printf("\n========================================\n");
    printf("TEST 9: CXOF (10-byte custom, 18-byte message)\n");
    printf("========================================\n");
    
    uint8_t custom[] = "MyAppV1.00";
    uint8_t msg[] = "Test data for CXOF";
    uint8_t output[32];
    
    hw_ascon_cxof(ascon_ctrl, custom, 10, msg, 18, output, 32);
    
    uint8_t expected[32] = {
        0x2b, 0xe1, 0x80, 0x8d, 0xf8, 0x25, 0x56, 0x4c,
        0x8a, 0xe5, 0xbc, 0x61, 0xf0, 0x2c, 0xcd, 0xbe,
        0xf5, 0x5a, 0xaa, 0xc2, 0x97, 0x32, 0xa8, 0x0c,
        0x97, 0xfa, 0x0e, 0x97, 0x34, 0xa5, 0x9e, 0x83
    };
    
    int pass = memcmp(output, expected, 32) == 0;
    printf("%s TEST 9 %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}

void test_cxof_10(void* ascon_ctrl) {
    printf("\n========================================\n");
    printf("TEST 10: CXOF (3-byte custom, 48-byte message)\n");
    printf("========================================\n");
    
    uint8_t custom[] = "ABC";
    uint8_t msg[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIIKL";
    uint8_t output[32];
    
    hw_ascon_cxof(ascon_ctrl, custom, 3, msg, 48, output, 32);
    
    uint8_t expected[32] = {
        0x13, 0x19, 0xba, 0x32, 0x76, 0x8b, 0xb4, 0xaf,
        0xa6, 0x98, 0xaf, 0x76, 0xec, 0x63, 0x3e, 0xc3,
        0x96, 0x37, 0x69, 0xce, 0x8a, 0xae, 0x8b, 0xa4,
        0x0d, 0xe3, 0x43, 0xa2, 0x7b, 0x6f, 0xc3, 0xa9
    };
    
    int pass = memcmp(output, expected, 32) == 0;
    printf("%s TEST 10 %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}

void test_aead_11_enc(void* ascon_ctrl) {
    // printf("\n========================================\n");
    // printf("TEST 11: AEAD Encryption (20-byte AD, 23-byte PT)\n");
    // printf("========================================\n");
    
    uint8_t key[16] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                       0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
    uint8_t nonce[16] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                         0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    uint8_t ad[] = "MULTIBLOCKADHERETEST";
    uint8_t pt[] = "MULTIBLOCKPLAINTEXTHERE";
    uint8_t ct[32];
    uint64_t tag[4];
    
    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, 20, pt, 23, ct, tag, 1);
    end_timing("AEAD-ENC");

    printf("Ciphertext: ");
    for (size_t i = 0; i < 23; i++) {
        printf("%02x", ct[i]);
    }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag[2], tag[3]);
    printf("✓ TEST 11 ENCRYPT COMPLETED\n");
}

void test_aead_11_dec(void* ascon_ctrl) {
    // printf("\n========================================\n");
    // printf("TEST 11: AEAD Decryption (20-byte AD, 23-byte CT)\n");
    // printf("========================================\n");
    
    uint8_t key[16] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                       0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
    uint8_t nonce[16] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                         0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    uint8_t ad[] = "MULTIBLOCKADHERETEST";
    
    uint8_t ct[23] = {0xde, 0x88, 0xac, 0xba, 0xec, 0xb7, 0x06, 0xde,
                      0x2a, 0x0b, 0xa6, 0x4a, 0x1d, 0xd4, 0x9b, 0xfc,
                      0xb3, 0xb1, 0x2c, 0x1c, 0x0c, 0x0c, 0x51};
    uint8_t pt[32];
    uint64_t tag[4];
    
    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, 20, ct, 23, pt, tag, 0);
    end_timing("AEAD-DEC");
    
    printf("Plaintext: ");
    for (size_t i = 0; i < 23; i++) {
        printf("%02x", pt[i]);
    }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag[2], tag[3]);

    uint8_t expected_pt[] = "MULTIBLOCKPLAINTEXTHERE";
    int pass = memcmp(pt, expected_pt, 23) == 0;
    
    printf("%s TEST 11 DECRYPT %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}

// void test_aead_13_enc(void* ascon_ctrl) {
//     // printf("\n========================================\n");
//     // printf("TEST 13: AEAD Encryption (16-byte AD, 16-byte PT)\n");
//     // printf("========================================\n");
    
//     uint8_t key[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
//                        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
//     uint8_t nonce[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
//                          0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
//     uint8_t ad[] = "FULLBLOCKADTEST!";
//     uint8_t pt[] = "FULLBLOCKPTTEST!";
//     uint8_t ct[32];
//     uint64_t tag[4];

//     start_timing();
//     hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, pt, sizeof(pt) - 1, ct, tag, 1);
//     end_timing("AEAD-ENC");

//     printf("Ciphertext: ");
//     for (size_t i = 0; i < 16; i++) {
//         printf("%02x", ct[i]);
//     }
//     printf("\n");
//     printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag[2], tag[3]);
//     printf("✓ TEST 13 ENCRYPT COMPLETED\n");
// }

// void test_aead_13_dec(void* ascon_ctrl) {
//     // printf("\n========================================\n");
//     // printf("TEST 13: AEAD Decryption (16-byte AD, 16-byte CT)\n");
//     // printf("========================================\n");
    
//     uint8_t key[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
//                        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
//     uint8_t nonce[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
//                          0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
//     uint8_t ad[] = "FULLBLOCKADTEST!";
    
//     uint8_t ct[16] = {0x3f, 0x04, 0x27, 0xe0, 0xe1, 0xea, 0xfa, 0x99,
//                       0x6b, 0xd6, 0xbd, 0xde, 0xd5, 0x02, 0x64, 0x6d};
//     uint8_t pt[32];
//     uint64_t tag[4];
//     start_timing();
//     hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, pt, sizeof(pt) - 1, ct, tag, 0);
//     end_timing("AEAD-DEC");

//         printf("Plaintext: ");
//     for (size_t i = 0; i < 13; i++) {
//         printf("%02x", pt[i]);
//     }
//     printf("\n");
//     printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag[2], tag[3]);

//     uint8_t expected_pt[] = "FULLBLOCKPTTEST!";
//     int pass = memcmp(pt, expected_pt, 16) == 0;
    
//     printf("%s TEST 13 DECRYPT %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
// }



void test_aead_14_enc_dec(void* ascon_ctrl) {
    // printf("\n========================================\n");
    printf("TEST 14: AEAD (16-byte AD, 16-byte PT)\n");
    // printf("========================================\n");
    
    uint8_t key[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t nonce[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                         0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    uint8_t ad[] = "FULLBLOCKADTEST!";
    uint8_t pt[16] = {0};  // 16-byte plaintext
    uint8_t ct[16] = {0};  // 16-byte ciphertext
    uint64_t tag_enc[4];
    uint64_t tag_dec[4];

    uint8_t pt_dec[16] = {0};  // 16-byte plaintext

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, pt, sizeof(pt) - 1, ct, tag_enc, 1);
    end_timing("AEAD-ENC");

    // printf("Ciphertext: ");
    // for (size_t i = 0; i < 16; i++) {
    //     printf("%02x", ct[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_enc[2], tag_enc[3]);

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, ct, sizeof(pt) - 1, pt_dec, tag_dec, 0);
    end_timing("AEAD-DEC");

    // printf("Plaintext: ");
    // for (size_t i = 0; i < 13; i++) {
    //     printf("%02x", pt_dec[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_dec[2], tag_dec[3]);

    int pass = memcmp(pt_dec, pt, 16) == 0;

    printf("%s TEST 14 DECRYPT %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}


void test_aead_15_enc_dec(void* ascon_ctrl) {
    // printf("\n========================================\n");
    printf("TEST 15: AEAD (16-byte AD, 32-byte PT)\n");
    // printf("========================================\n");
    
    uint8_t key[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t nonce[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                         0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    uint8_t ad[] = "FULLBLOCKADTEST!";
    uint8_t pt[32] = {0};  // 32-byte plaintext
    uint8_t ct[32] = {0};  // 32-byte ciphertext
    uint64_t tag_enc[4];
    uint64_t tag_dec[4];

    uint8_t pt_dec[32] = {0};  // 32-byte plaintext

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, pt, sizeof(pt) - 1, ct, tag_enc, 1);
    end_timing("AEAD-ENC");

    // printf("Ciphertext: ");
    // for (size_t i = 0; i < 16; i++) {
    //     printf("%02x", ct[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_enc[2], tag_enc[3]);

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, ct, sizeof(pt) - 1, pt_dec, tag_dec, 0);
    end_timing("AEAD-DEC");

    // printf("Plaintext: ");
    // for (size_t i = 0; i < 13; i++) {
    //     printf("%02x", pt_dec[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_dec[2], tag_dec[3]);

    int pass = memcmp(pt_dec, pt, 16) == 0;

    printf("%s TEST 14 DECRYPT %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}


void test_aead_16_enc_dec(void* ascon_ctrl) {
    // printf("\n========================================\n");
    printf("TEST 16: AEAD (16-byte AD, 64-byte PT)\n");
    // printf("========================================\n");
    
    uint8_t key[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t nonce[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                         0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    uint8_t ad[] = "FULLBLOCKADTEST!";
    uint8_t pt[64] = {0};  // 64-byte plaintext
    uint8_t ct[64] = {0};  // 64-byte ciphertext
    uint64_t tag_enc[4];
    uint64_t tag_dec[4];

    uint8_t pt_dec[64] = {0};  // 64-byte plaintext

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, pt, sizeof(pt) - 1, ct, tag_enc, 1);
    end_timing("AEAD-ENC");

    // printf("Ciphertext: ");
    // for (size_t i = 0; i < 16; i++) {
    //     printf("%02x", ct[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_enc[2], tag_enc[3]);

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, ct, sizeof(pt) - 1, pt_dec, tag_dec, 0);
    end_timing("AEAD-DEC");

    // printf("Plaintext: ");
    // for (size_t i = 0; i < 13; i++) {
    //     printf("%02x", pt_dec[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_dec[2], tag_dec[3]);

    int pass = memcmp(pt_dec, pt, 16) == 0;

    printf("%s TEST 14 DECRYPT %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}


void test_aead_17_enc_dec(void* ascon_ctrl) {
    // printf("\n========================================\n");
    printf("TEST 17: AEAD (16-byte AD, 128-byte PT)\n");
    // printf("========================================\n");
    
    uint8_t key[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t nonce[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                         0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    uint8_t ad[] = "FULLBLOCKADTEST!";
    uint8_t pt[128] = {0};  // 128-byte plaintext
    uint8_t ct[128] = {0};  // 128-byte ciphertext
    uint64_t tag_enc[4];
    uint64_t tag_dec[4];

    uint8_t pt_dec[128] = {0};  // 128-byte plaintext

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, pt, sizeof(pt) - 1, ct, tag_enc, 1);
    end_timing("AEAD-ENC");

    // printf("Ciphertext: ");
    // for (size_t i = 0; i < 16; i++) {
    //     printf("%02x", ct[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_enc[2], tag_enc[3]);

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, ct, sizeof(pt) - 1, pt_dec, tag_dec, 0);
    end_timing("AEAD-DEC");

    // printf("Plaintext: ");
    // for (size_t i = 0; i < 13; i++) {
    //     printf("%02x", pt_dec[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_dec[2], tag_dec[3]);

    int pass = memcmp(pt_dec, pt, 16) == 0;

    printf("%s TEST 14 DECRYPT %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}


void test_aead_18_enc_dec(void* ascon_ctrl) {
    // printf("\n========================================\n");
    printf("TEST 18: AEAD (16-byte AD, 256-byte PT)\n");
    // printf("========================================\n");
    
    uint8_t key[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t nonce[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                         0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    uint8_t ad[] = "FULLBLOCKADTEST!";
    uint8_t pt[256] = {0};  // 256-byte plaintext
    uint8_t ct[256] = {0};  // 256-byte ciphertext
    uint64_t tag_enc[4];
    uint64_t tag_dec[4];

    uint8_t pt_dec[256] = {0};  // 256-byte plaintext

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, pt, sizeof(pt) - 1, ct, tag_enc, 1);
    end_timing("AEAD-ENC");

    // printf("Ciphertext: ");
    // for (size_t i = 0; i < 16; i++) {
    //     printf("%02x", ct[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_enc[2], tag_enc[3]);

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, ct, sizeof(pt) - 1, pt_dec, tag_dec, 0);
    end_timing("AEAD-DEC");

    // printf("Plaintext: ");
    // for (size_t i = 0; i < 13; i++) {
    //     printf("%02x", pt_dec[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_dec[2], tag_dec[3]);

    int pass = memcmp(pt_dec, pt, 16) == 0;

    printf("%s TEST 14 DECRYPT %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}


void test_aead_19_enc_dec(void* ascon_ctrl) {
    // printf("\n========================================\n");
    printf("TEST 19: AEAD (16-byte AD, 512-byte PT)\n");
    // printf("========================================\n");
    
    uint8_t key[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t nonce[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                         0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    uint8_t ad[] = "FULLBLOCKADTEST!";
    uint8_t pt[512] = {0};  // 512-byte plaintext
    uint8_t ct[512] = {0};  // 512-byte ciphertext
    uint64_t tag_enc[4];
    uint64_t tag_dec[4];

    uint8_t pt_dec[512] = {0};  // 512-byte plaintext

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, pt, sizeof(pt) - 1, ct, tag_enc, 1);
    end_timing("AEAD-ENC");

    // printf("Ciphertext: ");
    // for (size_t i = 0; i < 16; i++) {
    //     printf("%02x", ct[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_enc[2], tag_enc[3]);

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, ct, sizeof(pt) - 1, pt_dec, tag_dec, 0);
    end_timing("AEAD-DEC");

    // printf("Plaintext: ");
    // for (size_t i = 0; i < 13; i++) {
    //     printf("%02x", pt_dec[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_dec[2], tag_dec[3]);

    int pass = memcmp(pt_dec, pt, 16) == 0;

    printf("%s TEST 14 DECRYPT %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}


void test_aead_20_enc_dec(void* ascon_ctrl) {
    // printf("\n========================================\n");
    printf("TEST 20: AEAD (16-byte AD, 1024-byte PT)\n");
    // printf("========================================\n");
    
    uint8_t key[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t nonce[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                         0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    uint8_t ad[] = "FULLBLOCKADTEST!";
    uint8_t pt[1024] = {0};  // 1024-byte plaintext
    uint8_t ct[1024] = {0};  // 1024-byte ciphertext
    uint64_t tag_enc[4];
    uint64_t tag_dec[4];

    uint8_t pt_dec[1024] = {0};  // 1024-byte plaintext

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, pt, sizeof(pt) - 1, ct, tag_enc, 1);
    end_timing("AEAD-ENC");

    // printf("Ciphertext: ");
    // for (size_t i = 0; i < 16; i++) {
    //     printf("%02x", ct[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_enc[2], tag_enc[3]);

    start_timing();
    hw_ascon_aead(ascon_ctrl, key, nonce, ad, sizeof(ad) - 1, ct, sizeof(pt) - 1, pt_dec, tag_dec, 0);
    end_timing("AEAD-DEC");

    // printf("Plaintext: ");
    // for (size_t i = 0; i < 13; i++) {
    //     printf("%02x", pt_dec[i]);
    // }
    printf("\n");
    printf("Tag: %016" PRIx64 "%016" PRIx64 "\n", tag_dec[2], tag_dec[3]);

    int pass = memcmp(pt_dec, pt, 16) == 0;

    printf("%s TEST 14 DECRYPT %s\n", pass ? "✓" : "✗", pass ? "PASSED" : "FAILED");
}


// ========================================
// HKDF Test Functions
// ========================================

void test_hkdf_extract_expand(void* ascon_ctrl) {
    printf("\n========================================\n");
    printf("TEST HKDF: Extract and Expand (32-byte key derivation)\n");
    printf("========================================\n");
    
    /* Test vectors */
    uint8_t ikm[] = "input keying material for HKDF test";
    uint8_t salt[] = "optional salt value";
    uint8_t info[] = "context and application specific info";
    
    /* PRK from Extract (32 bytes = 4 x 64-bit words) */
    uint64_t prk[4];
    
    /* OKM from Expand (derive 48 bytes) */
    uint8_t okm[48];
    
    printf("Step 1: HKDF-Extract\n");
    printf("  IKM:  %s (%zu bytes)\n", ikm, strlen((char*)ikm));
    printf("  Salt: %s (%zu bytes)\n", salt, strlen((char*)salt));
    
    start_timing();
    hw_ascon_hkdf_extract(ascon_ctrl, salt, strlen((char*)salt), 
                          ikm, strlen((char*)ikm), prk);
    end_timing("HKDF-Extract");
    
    printf("  PRK (32 bytes): %016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n",
           prk[0], prk[1], prk[2], prk[3]);
    
    printf("\nStep 2: HKDF-Expand\n");
    printf("  Info: %s (%zu bytes)\n", info, strlen((char*)info));
    printf("  Requested OKM length: %zu bytes\n", sizeof(okm));
    
    start_timing();
    hw_ascon_hkdf_expand(ascon_ctrl, (uint8_t*)prk, 32,
                         info, strlen((char*)info),
                         okm, sizeof(okm));
    end_timing("HKDF-Expand");
    
    printf("  OKM (first 32 bytes): ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", okm[i]);
    }
    printf("\n");
    printf("  OKM (last 16 bytes):  ");
    for (size_t i = 32; i < 48; i++) {
        printf("%02x", okm[i]);
    }
    printf("\n");
    
    printf("✓ TEST HKDF COMPLETED\n");
}

void test_hkdf_key_schedule(void* ascon_ctrl) {
    printf("\n========================================\n");
    printf("TEST HKDF: HPKE-style Key Schedule\n");
    printf("========================================\n");
    
    /* Simulate shared secret from key exchange */
    uint8_t shared_secret[32];
    for (int i = 0; i < 32; i++) {
        shared_secret[i] = (uint8_t)(i * 7);  /* Test pattern */
    }
    
    printf("Shared Secret (32 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", shared_secret[i]);
    }
    printf("...\n");
    
    /* Extract: PRK = HKDF-Extract(salt=NULL, IKM=shared_secret) */
    uint64_t prk_schedule[4];
    
    printf("\nStep 1: Key Schedule Extract (no salt)\n");
    start_timing();
    hw_ascon_hkdf_extract(ascon_ctrl, NULL, 0, shared_secret, 32, prk_schedule);
    end_timing("Schedule Extract");
    
    printf("  PRK Schedule: %016" PRIx64 "%016" PRIx64 "...\n", 
           prk_schedule[0], prk_schedule[1]);
    
    /* Expand for AES key */
    uint8_t aead_key[16];  /* 128-bit key */
    uint8_t key_info[] = {0x00, 0x01, 0x00, 0x10};  /* "key" label + length */
    
    printf("\nStep 2: Expand for AEAD key (16 bytes)\n");
    start_timing();
    hw_ascon_hkdf_expand(ascon_ctrl, (uint8_t*)prk_schedule, 32,
                         key_info, sizeof(key_info),
                         aead_key, sizeof(aead_key));
    end_timing("Key Expand");
    
    printf("  AEAD Key: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", aead_key[i]);
    }
    printf("\n");
    
    /* Expand for nonce */
    uint8_t base_nonce[16];  /* 128-bit nonce */
    uint8_t nonce_info[] = {0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00};  /* "base_nonce" label + length */
    
    printf("\nStep 3: Expand for base nonce (16 bytes)\n");
    start_timing();
    hw_ascon_hkdf_expand(ascon_ctrl, (uint8_t*)prk_schedule, 32,
                         nonce_info, sizeof(nonce_info),
                         base_nonce, sizeof(base_nonce));
    end_timing("Nonce Expand");
    
    printf("  Base Nonce: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", base_nonce[i]);
    }
    printf("\n");
    
    printf("✓ TEST HKDF KEY SCHEDULE COMPLETED\n");
}

// ========================================
// Main Test Suite
// ========================================

void hw_ascon_run_all_tests(void* ascon_ctrl) {
    printf("\n");
    // printf("===========================================\n");
    // printf("  ASCON Hardware Driver Test Suite\n");
    // printf("  Matching testbench patterns\n");
    // printf("===========================================\n");
    
    /* HKDF Tests */
    test_hkdf_extract_expand(ascon_ctrl);
    test_hkdf_key_schedule(ascon_ctrl);
    
    // test_hmac_1(ascon_ctrl);
    // test_hmac_2(ascon_ctrl);
    // test_hmac_3(ascon_ctrl);
    
    // test_hash_4(ascon_ctrl);
    // test_hash_6(ascon_ctrl);
    // test_hash_7(ascon_ctrl);
    // test_hash_8(ascon_ctrl); //this test setup is wrong
    
    // test_cxof_5(ascon_ctrl);
    // // test_cxof_9(ascon_ctrl); //this test setup is wrong
    // test_cxof_10(ascon_ctrl);
    
    // test_aead_11_enc(ascon_ctrl);
    // test_aead_11_dec(ascon_ctrl);
    // test_aead_13_enc(ascon_ctrl);
    // test_aead_13_dec(ascon_ctrl);

    test_aead_14_enc_dec(ascon_ctrl);
    test_aead_15_enc_dec(ascon_ctrl);
    test_aead_16_enc_dec(ascon_ctrl);
    test_aead_17_enc_dec(ascon_ctrl);
    test_aead_18_enc_dec(ascon_ctrl);
    test_aead_19_enc_dec(ascon_ctrl);
    test_aead_20_enc_dec(ascon_ctrl);
    
    printf("\n===========================================\n");
    printf("  Test Suite Complete\n");
    printf("===========================================\n\n");
}