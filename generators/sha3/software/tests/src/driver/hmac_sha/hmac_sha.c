#include "driver/hmac_sha/hmac_sha.h"
#include "mmio.h"
#include "encoding.h"

#define VERSION_HMAC 2
#define ADDR_KEY0 16
#define ADDR_KEY1 17
#define ADDR_KEY2 18
#define ADDR_KEY3 19
#define ADDR_KEY4 20
#define ADDR_KEY5 21
#define ADDR_KEY6 22
#define ADDR_KEY7 23
#define ADDR_MSGLENH 33
#define ADDR_MSGLENL 32
#define ADDR_STATUS  34
#define ADDR_DIGEST0 24
#define ADDR_DIGEST1 25
#define ADDR_DIGEST2 26
#define ADDR_DIGEST3 27
#define ADDR_DIGEST4 28
#define ADDR_DIGEST5 29
#define ADDR_DIGEST6 30
#define ADDR_DIGEST7 31
#define ADDR_INPUT 0

#define SHA 1
#define HMAC 2
#define SHA512 4
#define SHA384 2
#define SHA256 1

/*3’b100: 512-bits mode
 3’b010: 384-bits mode
 3’b001: 256-bits mode*/

void hmacsha_reset(void *hmac_shactrl)
{
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_RESETN) = 0;
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_ENABLE) = 0;
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_END_PACKET) = 0;
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_CONF_WE) = 0;
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_RESETN) = 1;
    //uart_put_hex((void *)uart_reg, _REG32((char *)hmac_shactrl, HMAC_SHA_REG_RESETN));
}

void hmacsha_write_conf(void *hmac_shactrl, uint32_t addr, uint64_t data)
{
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_CONF_ADDRESS) = addr;
    // _REG32((char *)hmac_shactrl, HMAC_SHA_REG_CONF_DATA_0) = (uint32_t)((data >> 32) & 0xFFFFFFFF);
    // _REG32((char *)hmac_shactrl, HMAC_SHA_REG_CONF_DATA_1) = (uint32_t)(data & 0xFFFFFFFF);
    _REG64((char *)hmac_shactrl, HMAC_SHA_REG_CONF_DATA) = data;
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_CONF_WE) = 1;
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_CONF_WE) = 0;
}

void hmacsha_end_packet(void *hmac_shactrl)
{
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_END_PACKET) = 1;
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_END_PACKET) = 0;
}

void hmacsha_set_key(void *hmac_shactrl, uint64_t *key)
{
    /*always assume key of 512 bits/64 bytes, need to verify by software*/
    for (int i = 0; i < 8; i++)
    {
        hmacsha_write_conf(hmac_shactrl, ADDR_KEY0 + i, key[i]);
    }
}

void hmacsha_set_length(void *hmac_shactrl, uint64_t *msj_len)
{
    hmacsha_write_conf(hmac_shactrl, ADDR_MSGLENH, msj_len[0]);
    hmacsha_write_conf(hmac_shactrl, ADDR_MSGLENL, msj_len[1]);
}

void hmacsha_write_status(void *hmac_shactrl, int mode, int submode)
{
    uint64_t config = (mode<<3 | submode ) & 0x0000001F;
    hmacsha_write_conf(hmac_shactrl, ADDR_STATUS, config);
}

int hmacsha_read_ready(void *hmac_shactrl)
{
    if(_REG32((char *)hmac_shactrl, HMAC_SHA_REG_READY) == 1){
        return 0;
    }else{
        return -1;
    }
}

int hmacsha_read_input_ready(void *hmac_shactrl)
{
    if(_REG32((char *)hmac_shactrl, HMAC_SHA_REG_INPUT_READY) == 1){
        return 0;
    }else{
        return -1;
    }
}

void hmacsha_enable(void *hmac_shactrl)
{
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_ENABLE)=1;
     #if VERSION_HMAC == 2
        _REG32((char *)hmac_shactrl, HMAC_SHA_REG_ENABLE)=0;
     #endif
}

void hmacsha_msj(void *hmac_shactrl, uint64_t *msg)
{
    for(int i=0; i<16;i++){
        // printf("  msg[%d] = 0x%016llx\n", i, msg[i]);
        hmacsha_write_conf(hmac_shactrl, ADDR_INPUT+i, msg[i]);
    }
}

void hmacsha_read_mac(void *hmac_shactrl, uint64_t *mac)
{
    //uint32_t config = hmacsha_read_ready(hmac_shactrl);
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_READY) = 1;
    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_READY) = 0;

    _REG32((char *)hmac_shactrl, HMAC_SHA_REG_CONF_WE) = 0;
    for (int i = 0; i < 8; i++)
    {
        _REG32((char *)hmac_shactrl, HMAC_SHA_REG_CONF_ADDRESS) = ADDR_DIGEST0 + i;
        // uint64_t tmp = _REG32((char *)hmac_shactrl, HMAC_SHA_REG_DOUT_0);
        #if VERSION_HMAC == 1
            mac[7-i] = (uint64_t)(_REG32((char *)hmac_shactrl, HMAC_SHA_REG_DOUT_1) | (tmp << 32));
        #elif VERSION_HMAC == 2
            mac[i] = _REG64((char *)hmac_shactrl, HMAC_SHA_REG_DOUT);
        #endif
    }
}

// /* Unified HMAC-SHA function that encapsulates all hardware operations */
// int hmacsha_compute(void *hmac_shactrl, 
//                    int hash_type,           /* SHA256, SHA384, SHA512 */
//                    uint64_t *key,           /* Key array (8 qwords) */
//                 //    int key_size_bytes,      /* Key size in bytes */
//                    uint64_t *message,       /* Message array (16 qwords) */
//                    int msg_size_bits,       /* Message size in bits */
//                    uint64_t *mac_output)    /* Output MAC (8 qwords) */
// {
//     // printf("HMAC-SHA%d computation starting...\n", 
//     //        hash_type == SHA256 ? 256 : hash_type == SHA384 ? 384 : 512);
    
//     /* Validate inputs */
//     if (!hmac_shactrl || !key || !message || !mac_output) {
//         // printf("ERROR: Invalid input parameters\n");
//         return -1;
//     }
    
//     // if (key_size_bytes > 64) {
//     //     printf("ERROR: Key too large (max 64 bytes)\n");
//     //     return -1;
//     // }
    
//     // if (msg_size_bits > (16 * 64)) {  /* 16 qwords × 64 bits = 1024 bits max */
//     //     printf("ERROR: Message too large (max 1024 bits)\n");
//     //     return -1;
//     // }
    
//     /* Prepare message length array */
//     uint64_t msg_len[2] = {0, msg_size_bits};
    
//     // printf("Key size: %d bytes\n", key_size_bytes);
//     // printf("Message size: %d bits\n", msg_size_bits);
    
//     /* Step 1: Reset hardware */
//     // printf("Step 1: Resetting hardware...\n");
//     hmacsha_reset(hmac_shactrl);
    
//     /* Step 2: Set message length */
//     // printf("Step 2: Setting message length...\n");
//     hmacsha_set_length(hmac_shactrl, msg_len);
    
//     /* Step 3: Configure mode (HMAC + hash type) */
//     // printf("Step 3: Configuring HMAC mode...\n");
//     hmacsha_write_status(hmac_shactrl, HMAC, hash_type);
    
//     /* Step 4: Set key */
//     // printf("Step 4: Setting key...\n");
//     hmacsha_set_key(hmac_shactrl, key);
    
//     /* Step 5: Enable hardware */
//     // printf("Step 5: Enabling hardware...\n");
//     hmacsha_enable(hmac_shactrl);
    
//     /* Step 6: Wait for input ready */
//     // printf("Step 6: Waiting for input ready...\n");
//     // int timeout = 1000000;  /* Timeout counter */
//     while(hmacsha_read_input_ready(hmac_shactrl) != 0) {
//         // if (--timeout == 0) {
//         //     printf("ERROR: Timeout waiting for input ready\n");
//         //     return -1;
//         // }
//     }
    
//     /* Step 7: Send message */
//     // printf("Step 7: Sending message...\n");
//     hmacsha_msj(hmac_shactrl, message);
    
//     /* Step 8: Signal end of packet */
//     // printf("Step 8: Signaling end of packet...\n");
//     hmacsha_end_packet(hmac_shactrl);
    
//     /* Step 9: Wait for completion */
//     // printf("Step 9: Waiting for completion...\n");
//     // timeout = 1000000;  /* Reset timeout */
//     while(hmacsha_read_ready(hmac_shactrl) != 0) {
//         // if (--timeout == 0) {
//         //     printf("ERROR: Timeout waiting for completion\n");
//         //     return -1;
//         // }
//     }
    
//     /* Step 10: Read MAC result */
//     // printf("Step 10: Reading MAC result...\n");
//     hmacsha_read_mac(hmac_shactrl, mac_output);
    
//     // printf("HMAC-SHA%d computation completed successfully!\n", 
//     //        hash_type == SHA256 ? 256 : hash_type == SHA384 ? 384 : 512);
    
//     return 0;  /* Success */
// }

/* Corrected hmacsha_compute for SHA-256 with 64-byte chunks */
int hmacsha_compute(void *hmac_shactrl, 
                   int hash_type,
                   uint64_t *key,
                   uint64_t *message,
                   int msg_size_bits,
                   uint64_t *mac_output)
{
    int msg_size_bytes = (msg_size_bits + 7) / 8;
    
    // int qwords_per_chunk = (hash_type == SHA256) ? 8 : 16;
    int bytes_per_chunk = 64;  /* 64 bytes = 8 qwords */
    int num_chunks = (msg_size_bytes + bytes_per_chunk - 1) / bytes_per_chunk;
    
    // printf("Message: %d bytes, %d-byte chunks, need %d chunks\n", 
    //        msg_size_bytes, bytes_per_chunk, num_chunks);
    
    /* Hardware setup */
    uint64_t msg_len[2] = {0, msg_size_bits};
    hmacsha_reset(hmac_shactrl);
    hmacsha_set_length(hmac_shactrl, msg_len);
    hmacsha_write_status(hmac_shactrl, HMAC, hash_type);
    hmacsha_set_key(hmac_shactrl, key);
    hmacsha_enable(hmac_shactrl);
    
    /* Send message in appropriate chunks */
    for (int chunk = 0; chunk < num_chunks; chunk++) {
        // printf("Sending chunk %d: bytes %d-%d\n", 
        //        chunk, chunk * bytes_per_chunk, (chunk + 1) * bytes_per_chunk - 1);
        
        while(hmacsha_read_input_ready(hmac_shactrl) != 0) {}
        // printf("Input ready for chunk %d\n", chunk);
        /* Pointer arithmetic to get current chunk */
        hmacsha_msj(hmac_shactrl, message + (chunk << 4));  /* chunk * 16 bytes */
        hmacsha_end_packet(hmac_shactrl);
    }
    
    while(hmacsha_read_ready(hmac_shactrl) != 0) {}
    hmacsha_read_mac(hmac_shactrl, mac_output);
    
    return 0;
}

// /* Convert MAC from Vietnamese pattern to hex string */
// void print_mac_as_hex_string(uint64_t *mac, const char *label)
// {
//     printf("%s: ", label);
    
//     /* Each qword contains 4 bytes in Vietnamese pattern (lower 32 bits) */
//     for (int i = 0; i < 8; i++) {
//         uint32_t word = (uint32_t)(mac[i] & 0xFFFFFFFF);
        
//         /* Extract 4 bytes from the 32-bit word in big-endian order */
//         unsigned char byte0 = (word >> 24) & 0xFF;
//         unsigned char byte1 = (word >> 16) & 0xFF;
//         unsigned char byte2 = (word >> 8) & 0xFF;
//         unsigned char byte3 = (word >> 0) & 0xFF;
        
//         printf("%02x%02x%02x%02x", byte0, byte1, byte2, byte3);
//     }
//     printf("\n");
// }

// /* RFC 4231 HMAC-SHA256 Test Vectors using hmacsha_compute */
// void test_hmacsha_compute_rfc4231(void *hmac_shactrl)
// {
//     printf("\n=== RFC 4231 HMAC-SHA256 Test Vectors (hmacsha_compute) ===\n");
    
//     int total_tests = 0;
//     int passed_tests = 0;
    
//     /* Test Case 1: Basic functionality test */
//     printf("\n--- RFC 4231 Test Case 1 ---\n");
//     printf("Key: 20 bytes of 0x0b\n");
//     printf("Data: 'Hi There' (8 bytes)\n");
    
//     {
//         uint64_t key1[8] = {0};
//         uint64_t msg1[16] = {0};
//         uint64_t mac1[8];
        
//         /* Key: 20 bytes of 0x0b in Vietnamese pattern */
//         /* 0x0b0b0b0b per 32-bit word */
//         key1[0] = 0x000000000b0b0b0bULL;  /* Bytes 0-3 */
//         key1[1] = 0x000000000b0b0b0bULL;  /* Bytes 4-7 */
//         key1[2] = 0x000000000b0b0b0bULL;  /* Bytes 8-11 */
//         key1[3] = 0x000000000b0b0b0bULL;  /* Bytes 12-15 */
//         key1[4] = 0x000000000b0b0b0bULL;  /* Bytes 16-19 */
//         /* Remaining key slots are 0 */
        
//         /* Data: "Hi There" = 0x4869205468657265 in Vietnamese pattern */
//         msg1[0] = 0x0000000048692054ULL;  /* "Hi T" */
//         msg1[1] = 0x0000000068657265ULL;  /* "here" */
        
//         /* Expected MAC: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 */
//         uint64_t expected1[8] = {
//             0x00000000b0344c61ULL, 0x00000000d8db3853ULL,
//             0x000000005ca8afceULL, 0x00000000af0bf12bULL,
//             0x00000000881dc200ULL, 0x00000000c9833da7ULL,
//             0x0000000026e9376cULL, 0x000000002e32cff7ULL
//         };
        
//         int result1 = hmacsha_compute(hmac_shactrl, SHA256, key1, msg1, 64, mac1);
//         total_tests++;
        
//         // printf("Result: %s\n", result1 == 0 ? "SUCCESS" : "FAILED");
//         if (result1 == 0) {
//             // printf("Computed MAC:\n");
//             // for (int i = 0; i < 8; i++) {
//             //     printf("  mac1[%d] = 0x%016llx\n", i, mac1[i]);
//             // }
            
//             /* Check if result matches expected */
//             int match = 1;
//             for (int i = 0; i < 8; i++) {
//                 if (mac1[i] != expected1[i]) {
//                     match = 0;
//                     break;
//                 }
//             }
            
//             printf("Expected MAC: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7\n");
//             print_mac_as_hex_string(mac1, "Computed MAC");
//             printf("Test Case 1: %s\n", match ? "PASS " : "FAIL ");
//             if (match) passed_tests++;
//         }
//     }
    
//     /* Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?" */
//     printf("\n--- RFC 4231 Test Case 2 ---\n");
//     printf("Key: 'Jefe' (4 bytes)\n");
//     printf("Data: 'what do ya want for nothing?' (28 bytes)\n");
    
//     {
//         uint64_t key2[8] = {0};
//         uint64_t msg2[16] = {0};
//         uint64_t mac2[8];
        
//         /* Key: "Jefe" = 0x4a656665 in Vietnamese pattern */
//         key2[0] = 0x000000004a656665ULL;
        
//         /* Data: "what do ya want for nothing?" in Vietnamese pattern */
//         /* "what" = 0x77686174, " do " = 0x20646f20 */
//         /* "ya w" = 0x79612077, "ant " = 0x616e7420 */
//         /* "for " = 0x666f7220, "noth" = 0x6e6f7468 */
//         /* "ing?" = 0x696e673f */
//         msg2[0] = 0x0000000077686174ULL;  /* "what" */
//         msg2[1] = 0x0000000020646f20ULL;  /* " do " */
//         msg2[2] = 0x0000000079612077ULL;  /* "ya w" */
//         msg2[3] = 0x00000000616e7420ULL;  /* "ant " */
//         msg2[4] = 0x00000000666f7220ULL;  /* "for " */
//         msg2[5] = 0x000000006e6f7468ULL;  /* "noth" */
//         msg2[6] = 0x00000000696e673fULL;  /* "ing?" */
        
//         /* Expected MAC: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 */
//         uint64_t expected2[8] = {
//             0x000000005bdcc146ULL, 0x00000000bf60754eULL,
//             0x000000006a042426ULL, 0x00000000089575c7ULL,
//             0x000000005a003f08ULL, 0x000000009d273983ULL,
//             0x000000009dec58b9ULL, 0x0000000064ec3843ULL
//         };
        
//         int result2 = hmacsha_compute(hmac_shactrl, SHA256, key2, msg2, 224, mac2);
//         total_tests++;
        
//         // printf("Result: %s\n", result2 == 0 ? "SUCCESS" : "FAILED");
//         if (result2 == 0) {
//             // printf("Computed MAC:\n");
//             // for (int i = 0; i < 8; i++) {
//             //     printf("  mac2[%d] = 0x%016llx\n", i, mac2[i]);
//             // }
            
//             /* Check if result matches expected */
//             int match = 1;
//             for (int i = 0; i < 8; i++) {
//                 if (mac2[i] != expected2[i]) {
//                     match = 0;
//                     break;
//                 }
//             }
            
//             printf("Expected MAC: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843\n");
//             print_mac_as_hex_string(mac2, "Computed MAC");
//             printf("Test Case 2: %s\n", match ? "PASS " : "FAIL ");
//             if (match) passed_tests++;
//         }
//     }
    
//     /* Test Case 3: 50-byte key and data */
//     printf("\n--- RFC 4231 Test Case 3 ---\n");
//     printf("Key: 20 bytes of 0xaa\n");
//     printf("Data: 50 bytes of 0xdd\n");
    
//     {
//         uint64_t key3[8] = {0};
//         uint64_t msg3[16] = {0};
//         uint64_t mac3[8];
//         /* CORRECT: Pack 20 bytes of 0xaa into Vietnamese pattern */
//         for (int i = 0; i < 20; i++) {
//             int qword_idx = i / 4;
//             int byte_pos = 3 - (i % 4);
//             if (qword_idx < 8) {
//                 key3[qword_idx] |= ((uint64_t)0xaa) << (8 * byte_pos);
//             }
//         }
        
//         /* CORRECT: Pack 50 bytes of 0xdd into Vietnamese pattern */
//         for (int i = 0; i < 50; i++) {
//             int qword_idx = i / 4;
//             int byte_pos = 3 - (i % 4);
//             if (qword_idx < 16) {
//                 msg3[qword_idx] |= ((uint64_t)0xdd) << (8 * byte_pos);
//             }
//         }
//             /* Debug: Show the pattern */
//         // printf("Key pattern (first 4 qwords):\n");
//         // for (int i = 0; i < 8; i++) {
//         //     printf("  key3[%d] = 0x%016llx\n", i, key3[i]);
//         // }
        
//         // printf("Message pattern (first 4 qwords):\n");
//         // for (int i = 8; i < 11; i++) {
//         //     printf("  msg3[%d] = 0x%016llx\n", i, msg3[i]);
//         // }
        
//         /* Expected MAC: 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe */
//         uint64_t expected3[8] = {
//             0x00000000773ea91eULL, 0x0000000036800e46ULL,
//             0x00000000854db8ebULL, 0x00000000d09181a7ULL,
//             0x000000002959098bULL, 0x000000003ef8c122ULL,
//             0x00000000d9635514ULL, 0x00000000ced565feULL
//         };
        
//         int result3 = hmacsha_compute(hmac_shactrl, SHA256, key3, msg3, 400, mac3);
//         total_tests++;
        
//         // printf("Result: %s\n", result3 == 0 ? "SUCCESS" : "FAILED");
//         if (result3 == 0) {
//             // printf("Computed MAC:\n");
//             // for (int i = 0; i < 8; i++) {
//             //     printf("  mac3[%d] = 0x%016llx\n", i, mac3[i]);
//             // }
            
//             /* Check if result matches expected */
//             int match = 1;
//             for (int i = 0; i < 8; i++) {
//                 if (mac3[i] != expected3[i]) {
//                     match = 0;
//                     break;
//                 }
//             }
            
//             printf("Expected MAC: 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe\n");
//             print_mac_as_hex_string(mac3, "Computed MAC");
//             printf("Test Case 3: %s\n", match ? "PASS " : "FAIL ");
//             if (match) passed_tests++;
//         }
//     }

//     /* Test Case 4: 25-byte key, 50-byte data */
//     printf("\n--- RFC 4231 Test Case 4 ---\n");
//     printf("Key: 25 bytes (0x0102030405060708090a0b0c0d0e0f10111213141516171819)\n");
//     printf("Data: 50 bytes of 0xcd\n");

//     {
//         uint64_t key4[8] = {0};
//         uint64_t msg4[16] = {0};
//         uint64_t mac4[8];
        
//         /* CORRECTED: 25-byte incremental key in Vietnamese pattern */
//         unsigned char key_bytes[25] = {
//             0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
//             0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
//             0x15, 0x16, 0x17, 0x18, 0x19
//         };
        
//         /* Pack 25-byte key into Vietnamese pattern */
//         for (int i = 0; i < 25; i++) {
//             int qword_idx = i / 4;
//             int byte_pos = 3 - (i % 4);
//             if (qword_idx < 8) {
//                 key4[qword_idx] |= ((uint64_t)key_bytes[i]) << (8 * byte_pos);
//             }
//         }
        
//         /* CORRECT: Pack 50 bytes of 0xcd into Vietnamese pattern */
//         for (int i = 0; i < 50; i++) {
//             int qword_idx = i / 4;
//             int byte_pos = 3 - (i % 4);
//             if (qword_idx < 16) {
//                 msg4[qword_idx] |= ((uint64_t)0xcd) << (8 * byte_pos);
//             }
//         }
        
//         /* Debug: Show the corrected key pattern */
//         // printf("Corrected key pattern (Vietnamese):\n");
//         // for (int i = 0; i < 7; i++) {
//         //     if (key4[i] != 0) {
//         //         printf("  key4[%d] = 0x%016llx\n", i, key4[i]);
//         //     }
//         // }
        
//         /* Expected: 82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b */
//         uint64_t expected4[8] = {
//             0x0000000082558a38ULL, 0x000000009a443c0eULL,
//             0x00000000a4cc8198ULL, 0x0000000099f2083aULL,
//             0x0000000085f0faa3ULL, 0x00000000e578f807ULL,
//             0x000000007a2e3ff4ULL, 0x000000006729665bULL
//         };
        
//         int result4 = hmacsha_compute(hmac_shactrl, SHA256, key4, msg4, 400, mac4);
//         total_tests++;
        
//         printf("Result: %s\n", result4 == 0 ? "SUCCESS" : "FAILED");
//         if (result4 == 0) {
//             // printf("Computed MAC: ");
//             // for (int i = 0; i < 8; i++) {
//             //     printf("%08x", (uint32_t)(mac4[i] & 0xFFFFFFFF));
//             // }
//             printf("\n");
//             printf("Expected MAC: 82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b\n");
//             print_mac_as_hex_string(mac4, "Computed MAC");
            
//             /* Check if result matches expected */
//             int match = 1;
//             for (int i = 0; i < 8; i++) {
//                 if (mac4[i] != expected4[i]) {
//                     match = 0;
//                     break;
//                 }
//             }
//             printf("Test Case 4: %s\n", match ? "PASS " : "FAIL");
//             if (match) passed_tests++;
//         }
//     }
    
    
//     /* Summary */
//     printf("\n=== RFC 4231 Test Summary ===\n");
//     printf("Total tests: %d\n", total_tests);
//     printf("Passed tests: %d\n", passed_tests);
//     printf("Failed tests: %d\n", total_tests - passed_tests);
    
//     if (passed_tests == total_tests) {
//         printf("ALL RFC 4231 TESTS PASSED!\n");
//     } else {
//         printf("SOME TESTS FAILED\n");
//     }
// }
// /* Test case simulating HKDF Expand with 65-byte message */
// void hwhmacsha_test_hkdf_expand_65bytes(void *hmac_shactrl)
// {
//     printf("\n=== HKDF Expand Simulation: 65-Byte Message ===\n");
//     printf("Simulating: T(0) + KEM_context(64) + counter(1) = 65 bytes\n");
    
//     /* Simulate HKDF Expand iteration 1 message structure */
//     unsigned char hkdf_msg[65];  /* Changed from byte to unsigned char */
//     int offset = 0;
    
//     /* No T(i-1) for first iteration (T(0) is empty) */
    
//     /* Add 64-byte KEM context (simulated as ephemeral_pk || receiver_pk) */
//     printf("Adding 64-byte KEM context...\n");
//     for (int i = 0; i < 32; i++) {
//         hkdf_msg[offset + i] = 0x11 + i;  /* Simulated ephemeral public key */
//     }
//     offset += 32;
    
//     for (int i = 0; i < 32; i++) {
//         hkdf_msg[offset + i] = 0x33 + i;  /* Simulated receiver public key */
//     }
//     offset += 32;
    
//     /* Add counter byte */
//     printf("Adding counter byte (0x01)...\n");
//     hkdf_msg[offset] = 0x01;  /* Counter for iteration 1 */
//     offset += 1;
    
//     printf("Total HKDF message length: %d bytes\n", offset);
    
//     /* 32-byte PRK as key */
//     unsigned char prk_key[32];  /* Changed from byte to unsigned char */
//     for (int i = 0; i < 32; i++) {
//         prk_key[i] = 0x77;  /* Simulated PRK */
//     }
    
//     /* Convert to Vietnamese pattern */
//     uint64_t key_hkdf[8] = {0};
//     uint64_t msg_hkdf[32] = {0};
//     uint64_t mac_hkdf[8];
    
//     /* Pack PRK as key */
//     for (int i = 0; i < 32; i++) {
//         int qw_idx = i / 4;
//         int byte_idx = 3 - (i % 4);
//         if (qw_idx < 8) {
//             key_hkdf[qw_idx] |= ((uint64_t)prk_key[i]) << (8 * byte_idx);
//         }
//     }
    
//     /* Pack HKDF message */
//     for (int i = 0; i < 65; i++) {
//         int qw_idx = i / 4;
//         int byte_idx = 3 - (i % 4);
//         if (qw_idx < 32) {
//             msg_hkdf[qw_idx] |= ((uint64_t)hkdf_msg[i]) << (8 * byte_idx);
//         }
//     }
    
//     printf("\nHKDF PRK key (Vietnamese pattern):\n");
//     for (int i = 0; i < 8; i++) {
//         if (key_hkdf[i] != 0) {
//             printf("  prk[%d] = 0x%016llx\n", i, key_hkdf[i]);
//         }
//     }
    
//     printf("\nHKDF message structure:\n");
//     printf("  Bytes 0-31:  Ephemeral public key\n");
//     printf("  Bytes 32-63: Receiver public key\n");
//     printf("  Byte 64:     Counter (0x01)\n");
    
//     /* Execute HMAC */
//     printf("\nExecuting HKDF Expand HMAC (65 bytes)...\n");
    
//     int result = hmacsha_compute(hmac_shactrl, 
//                                SHA256,
//                                key_hkdf,
//                                msg_hkdf,
//                                65 * 8,        /* 520 bits */
//                                mac_hkdf);
    
//     if (result == 0) {
//         printf("\n✅ HKDF Expand 65-byte HMAC successful!\n");
//         printf("This proves your hardware can handle HKDF Expand messages!\n");
        
//         printf("\nT(1) result (Vietnamese pattern):\n");
//         for (int i = 0; i < 8; i++) {
//             printf("  t1[%d] = 0x%016llx\n", i, mac_hkdf[i]);
//         }
        
//         /* Convert to bytes (this would be your T(1) for next iteration) */
//         unsigned char t1_bytes[32];  /* Changed from byte to unsigned char */
//         for (int i = 0; i < 8; i++) {
//             uint32_t lower_32 = (uint32_t)(mac_hkdf[i] & 0xFFFFFFFF);
//             t1_bytes[i*4+0] = (lower_32 >> 24) & 0xFF;
//             t1_bytes[i*4+1] = (lower_32 >> 16) & 0xFF;
//             t1_bytes[i*4+2] = (lower_32 >> 8) & 0xFF;
//             t1_bytes[i*4+3] = (lower_32 >> 0) & 0xFF;
//         }
        
//         printf("\nT(1) as bytes: ");
//         for (int i = 0; i < 32; i++) {
//             printf("%02x", t1_bytes[i]);
//         }
//         printf("\n");
        
//     } else {
//         printf("\n❌ HKDF Expand 65-byte HMAC failed: %d\n", result);
//         printf("Your chunking implementation needs fixing\n");
//     }
// }

// void hwhmacsha_selftest(void *hmac_shactrl)
// {

//       //=================== test hmac_sha_256 ===========================
//     // printf("HMAC-SHA 256: \n\r");
//     // uint32_t ref256[8] =    {0x507ed7ce, 0x53a9c1c2, 0x080f8996, 0x20fd0f59, 0x0c736a54, 0x727fa0ca, 0x1e80df27, 0x377c3939};
//     uint64_t msg256[16] =   {0x000000000b0b0b0b, 0x000000000b0b0b0b, 0x000000000b0b0b0b, 0x000000000b0b0b0b, // Hoc vien ky thuat mat ma.
//                              0x000000000b0b0b0b, 0x000000000b0b0000, 0x0000000000000000, 0x0000000000000000,
//                              0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
//                              0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
//                             };
//     uint64_t key256[8] = {0x0000000000010203,0x0000000004050607,0x0000000008090a0b,0x000000000c000000,0,0,0,0};
//     uint64_t mac256[8];
//     uint64_t msj_len256[2] = {0, 176};
    
//     // int key_size = 0;      /* 4 bytes effective key size */
//     int msg_size = 176;    /* 176 bits message size */

//     int cnt = 0;
    
// //     for (int i = 0; i < 8; i++) {
// //        printf("msg256[%d] = 0x%016llx\n", i, msg256[i]);
// //    }
//         /* Call unified HMAC-SHA function */
//     int result = hmacsha_compute(hmac_shactrl, 
//                                SHA256,           /* Hash type */
//                                key256,           /* Key */
//                             //    key_size,         /* Key size in bytes */
//                                msg256,           /* Message */
//                                msg_size,         /* Message size in bits */
//                                mac256);          /* Output MAC */
    
//     /* Check result and display output */
//     if (result == 0) {
//         printf("\n✅ HMAC computation successful!\n");
//         printf("MAC256 result:\n");
//         for (int i = 0; i < 8; i++) {
//             printf("  mac256[%d] = 0x%016llx\n", i, mac256[i]);
//         }
        
//         /* Print as continuous hex string for verification */
//         printf("\nMAC as hex string: ");
//         for (int i = 0; i < 8; i++) {
//             printf("%016llx", mac256[i]);
//         }
//         printf("\n");
//     } else {
//         printf("\n❌ HMAC computation failed with error: %d\n", result);
//     }

//     hmacsha_reset(hmac_shactrl);
//     hmacsha_set_length(hmac_shactrl, msj_len256);
//     hmacsha_write_status(hmac_shactrl, HMAC, SHA256);
//     hmacsha_set_key(hmac_shactrl, key256);
//     hmacsha_enable(hmac_shactrl);
//     while(hmacsha_read_input_ready(hmac_shactrl)!= 0){}
//     hmacsha_msj(hmac_shactrl, msg256);
//     hmacsha_end_packet(hmac_shactrl);
//     while(hmacsha_read_ready(hmac_shactrl)!= 0){}
//     hmacsha_read_mac(hmac_shactrl, mac256);

//    for (int i = 0; i < 8; i++) {
//        printf("mac256[%d] = 0x%016llx\n", i, mac256[i]);
//    }

    // for (int i = 0; i < 8; i++){
    //     if(mac256[i] != ref256[i]) cnt++;
    // }
    // if (cnt) printf("---Test failed!!!\n\r");
    // else  printf("+++Test passed!!!\n\r");



//     uint64_t msg256[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
//     uint64_t key256[8] = {0,0,0,0,0,0,0,0};
//     int msg_len = 16;
//     uint64_t mac256[8];
//     uint64_t msj_len256[2] = {0, 224};
//     //

//     msg256[0] = 0x00000000486f6320ULL; // "Hoc "
//     msg256[1] = 0x000000007669656eULL; // "vien"
//     msg256[2] = 0x00000000206b7920ULL; // " ky "
//     msg256[3] = 0x0000000074687561ULL; // "thuat"
//     msg256[4] = 0x0000000074206d61ULL; // " ma "
//     msg256[5] = 0x0000000074206d61ULL; // " ma "
//     msg256[6] = 0x0000000000002e20ULL; // Ph?n cu?i

//     //uart_puts((void *)uart_reg, "Reset: \n\n");
//     // printf("Reset: \n\n");
//     hmacsha_reset(hmac_shactrl);
//     //uart_puts((void *)uart_reg, "Set lenght: \n\n");
//     // printf("Set length: \n\n");
//     hmacsha_set_lenght(hmac_shactrl, msj_len256);
//     //uart_puts((void *)uart_reg, "Write status: \n\n");
//     // printf("Write status: \n\n");
//     hmacsha_write_status(hmac_shactrl, HMAC, SHA256);
//     //uart_puts((void *)uart_reg, "Set key: \n\n");
//     // printf("Set key: \n\n");
//     hmacsha_set_key(hmac_shactrl, key256);
//     hmacsha_enable(hmac_shactrl);
//     while(hmacsha_read_input_ready(hmac_shactrl)!= 0){
//         //uart_puts((void *)uart_reg, "Wait input ready: \n\n");
//         printf("Wait input ready: \n\n");
//     }

//     //uart_puts((void *)uart_reg, "Set msg: \n\n");
//     printf("Set msg: \n\n");
//     for (int i = 0; i < msg_len/16; i++)
//     {
//         hmacsha_msj(hmac_shactrl, msg256);
//     }
//     //uart_puts((void *)uart_reg, "End packet: \n\n");
//     printf("End packet: \n\n");
//     hmacsha_end_packet(hmac_shactrl);
//     while(hmacsha_read_ready(hmac_shactrl)!= 0){
//         //uart_puts((void *)uart_reg, "Wait ready: \n\n");
//         printf("Wait ready: \n\n"); 
//     }

//     //uart_puts((void *)uart_reg, "Get mac: \n\n");
//     printf("Get mac: \n\n");
//     hmacsha_read_mac(hmac_shactrl, mac256);

//    printf("Complete MAC256 result:\n");
//    for (int i = 0; i < 8; i++) {
//        printf("mac256[%d] = 0x%016llx\n", i, mac256[i]);
//    }


// }

// /* RFC 4231 Test Vectors for HMAC-SHA256 */
// void hwhmacsha_rfc4231_tests(void *hmac_shactrl)
// {
//     printf("\n=== RFC 4231 HMAC-SHA256 Test Vectors ===\n");
    
//     /* Test Case 1: Basic functionality test */
//     printf("\n--- RFC 4231 Test Case 1 ---\n");
//     printf("Key: 20 bytes of 0x0b\n");
//     printf("Data: 'Hi There'\n");
    
//     uint64_t key1[8] = {0};
//     uint64_t msg1[16] = {0};
//     uint64_t mac1[8];
//     uint64_t msj_len1[2] = {0, 64}; /* 8 bytes = 64 bits */
    
//     /* Key: 20 bytes of 0x0b (0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b) */
//     key1[0] = 0x0b0b0b0b0b0b0b0bULL;
//     key1[1] = 0x0b0b0b0b0b0b0b0bULL;
//     key1[2] = 0x0b0b0b0b00000000ULL; /* Last 4 bytes of 0x0b, rest zeros */
    
//     /* Data: "Hi There" = 0x4869205468657265 */
//     msg1[0] = 0x4869205468657265ULL;
    
//     /* Expected MAC: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 */
    
//     hmacsha_reset(hmac_shactrl);
//     hmacsha_set_lenght(hmac_shactrl, msj_len1);
//     hmacsha_write_status(hmac_shactrl, HMAC, SHA256);
//     hmacsha_set_key(hmac_shactrl, key1);
//     hmacsha_enable(hmac_shactrl);
    
//     while(hmacsha_read_input_ready(hmac_shactrl) != 0) {}
//     hmacsha_msj(hmac_shactrl, msg1);
//     hmacsha_end_packet(hmac_shactrl);
//     while(hmacsha_read_ready(hmac_shactrl) != 0) {}
//     hmacsha_read_mac(hmac_shactrl, mac1);
    
//     printf("Result MAC:\n");
//     for (int i = 0; i < 8; i++) {
//         printf("mac1[%d] = 0x%016llx\n", i, mac1[i]);
//     }
//     printf("Expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7\n");
    
//     /* Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?" */
//     printf("\n--- RFC 4231 Test Case 2 ---\n");
//     printf("Key: 'Jefe'\n");
//     printf("Data: 'what do ya want for nothing?'\n");
    
//     uint64_t key2[8] = {0};
//     uint64_t msg2[16] = {0};
//     uint64_t mac2[8];
//     uint64_t msj_len2[2] = {0, 224}; /* 28 bytes = 224 bits */
    
//     /* Key: "Jefe" = 0x4a656665 */
//     key2[0] = 0x4a65666500000000ULL;
    
//     /* Data: "what do ya want for nothing?" */
//     /* Convert string to hex qwords */
//     char *data2_str = "what do ya want for nothing?";
//     /* "what do " = 0x7768617420646f20 */
//     /* "ya want " = 0x796120776120666f */
//     /* "for noth" = 0x666f72206e6f7468 */
//     /* "ing?" + padding = 0x696e673f00000000 */
//     msg2[0] = 0x7768617420646f20ULL;
//     msg2[1] = 0x7961207761206e74ULL;
//     msg2[2] = 0x20666f72206e6f74ULL;
//     msg2[3] = 0x68696e673f000000ULL;
    
//     /* Expected MAC: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 */
    
//     hmacsha_reset(hmac_shactrl);
//     hmacsha_set_lenght(hmac_shactrl, msj_len2);
//     hmacsha_write_status(hmac_shactrl, HMAC, SHA256);
//     hmacsha_set_key(hmac_shactrl, key2);
//     hmacsha_enable(hmac_shactrl);
    
//     while(hmacsha_read_input_ready(hmac_shactrl) != 0) {}
//     hmacsha_msj(hmac_shactrl, msg2);
//     hmacsha_end_packet(hmac_shactrl);
//     while(hmacsha_read_ready(hmac_shactrl) != 0) {}
//     hmacsha_read_mac(hmac_shactrl, mac2);
    
//     printf("Result MAC:\n");
//     for (int i = 0; i < 8; i++) {
//         printf("mac2[%d] = 0x%016llx\n", i, mac2[i]);
//     }
//     printf("Expected: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843\n");
    
//     /* Test Case 3: 50-byte key of 0xaa */
//     printf("\n--- RFC 4231 Test Case 3 ---\n");
//     printf("Key: 50 bytes of 0xaa\n");
//     printf("Data: 50 bytes of 0xdd\n");
    
//     uint64_t key3[8] = {0};
//     uint64_t msg3[16] = {0};
//     uint64_t mac3[8];
//     uint64_t msj_len3[2] = {0, 400}; /* 50 bytes = 400 bits */
    
//     /* Key: 50 bytes of 0xaa (fill first 6.25 qwords) */
//     for (int i = 0; i < 6; i++) {
//         key3[i] = 0xaaaaaaaaaaaaaaaaULL;
//     }
//     key3[6] = 0xaaaa000000000000ULL; /* Last 2 bytes of 0xaa */
    
//     /* Data: 50 bytes of 0xdd */
//     for (int i = 0; i < 6; i++) {
//         msg3[i] = 0xddddddddddddddddULL;
//     }
//     msg3[6] = 0xdddd000000000000ULL; /* Last 2 bytes of 0xdd */
    
//     /* Expected MAC: 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe */
    
//     hmacsha_reset(hmac_shactrl);
//     hmacsha_set_lenght(hmac_shactrl, msj_len3);
//     hmacsha_write_status(hmac_shactrl, HMAC, SHA256);
//     hmacsha_set_key(hmac_shactrl, key3);
//     hmacsha_enable(hmac_shactrl);
    
//     while(hmacsha_read_input_ready(hmac_shactrl) != 0) {}
//     hmacsha_msj(hmac_shactrl, msg3);
//     hmacsha_end_packet(hmac_shactrl);
//     while(hmacsha_read_ready(hmac_shactrl) != 0) {}
//     hmacsha_read_mac(hmac_shactrl, mac3);
    
//     printf("Result MAC:\n");
//     for (int i = 0; i < 8; i++) {
//         printf("mac3[%d] = 0x%016llx\n", i, mac3[i]);
//     }
//     printf("Expected: 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe\n");
// }
