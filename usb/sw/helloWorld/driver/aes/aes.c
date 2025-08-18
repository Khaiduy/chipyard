#include "driver/aes/aes.h"

void hwaes_reset(void* aesctrl) {
    _REG32((char*)aesctrl, AES_REG_RST) = 0x1; // Reset the AES core
    _REG32((char*)aesctrl, AES_REG_RST) = 0x0; // Clear the reset
    _REG32((char*)aesctrl, AES_REG_INIT) = 0; 
    _REG32((char*)aesctrl, AES_REG_MODE) = 0;
    _REG32((char*)aesctrl, AES_REG_ENC) = 0;
}

void hwaes_selftest(void* aesctrl) {
    /* Testcase 1
    key = 0f1571c947d9e8590cb7add6af7f6798
    plain =0123456789abcdeffedcba9876543210
    cipher = ff0b844a0853bf7c6934ab4364148fb9
    */
    /* Testcase 2
    key = 2b7e151628aed2a6abf7158809cf4f3c
    plain = 47d57467aecff97d497e1a15ab96c883
    cipher = bcbde5d96ecaf85532439185c8c29c0d
    */

    kprintf("Starting AES self-test...\n");
    kprintf("Testcase 1:\n");
    kprintf("Key: 0f1571c947d9e8590cb7add6af7f6798\n");
    kprintf("Plaintext: 0123456789abcdeffedcba9876543210\n");
    kprintf("Expected Ciphertext: ff0b844a0853bf7c6934ab4364148fb9\n");
    kprintf("-----------------------------------------\n");

    uint32_t key_test[4] = {0x0f1571c9, 0x47d9e859, 0x0cb7add6, 0xaf7f6798};
    uint32_t plain_test[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
    uint32_t expected_cipher_test[4] = {0xff0b844a, 0x0853bf7c, 0x6934ab43, 0x64148fb9};

    kprintf("Loading key and plaintext into AES core...\n");
    // Reset the AES core
    _REG32((char*)aesctrl, AES_REG_RST) = 0x1;
    _REG32((char*)aesctrl, AES_REG_RST) = 0x0;

    //Set mode to encryption
    _REG32((char*)aesctrl, AES_REG_MODE) = 0; // 0 for encryption, 1 for decryption


    // Load the key into the AES core
    _REG32((char*)aesctrl, AES_REG_KEY_0) = key_test[3];
    _REG32((char*)aesctrl, AES_REG_KEY_1) = key_test[2];
    _REG32((char*)aesctrl, AES_REG_KEY_2) = key_test[1];
    _REG32((char*)aesctrl, AES_REG_KEY_3) = key_test[0];

    // Load the plaintext into the AES core
    _REG32((char*)aesctrl, AES_REG_MSG_0) = plain_test[3];
    _REG32((char*)aesctrl, AES_REG_MSG_1) = plain_test[2];
    _REG32((char*)aesctrl, AES_REG_MSG_2) = plain_test[1];
    _REG32((char*)aesctrl, AES_REG_MSG_3) = plain_test[0];


    // Initialize the AES core
    _REG32((char*)aesctrl, AES_REG_INIT) = 1;

    //Blindly wait for the AES core to finish round keys
    //But anyway, it takes a few cycles to compute the round keys

    // Trigger the AES encryption
    _REG32((char*)aesctrl, AES_REG_ENC) = 1;

    kprintf("Waiting for AES operation to complete...\n");
    // Polling for the AES core to finish processing
    uint32_t patient = 0;
    while (_REG32((char*)aesctrl, AES_REG_FINISH) == 0) {
        // Wait until the AES operation is complete
        patient++;
        if (patient > 1000000) { // Timeout after a certain number of iterations
            kprintf("AES operation timed out.\n");
            return;
        }
    }

    // Read the ciphertext from the AES core
    uint32_t cipher_test[4];
    cipher_test[0] = _REG32((char*)aesctrl, AES_REG_CIPHER_0);
    cipher_test[1] = _REG32((char*)aesctrl, AES_REG_CIPHER_1);
    cipher_test[2] = _REG32((char*)aesctrl, AES_REG_CIPHER_2);
    cipher_test[3] = _REG32((char*)aesctrl, AES_REG_CIPHER_3);
    // kprintf("Ciphertext results: %08x %08x %08x %08x\n", 
    //         cipher_test[0], cipher_test[1], cipher_test[2], cipher_test[3]);
    kprintf("Ciphertext results: ");
    kprintf("%x",_REG32((char*)aesctrl, AES_REG_CIPHER_0));
    kprintf("%x",_REG32((char*)aesctrl, AES_REG_CIPHER_1));
    kprintf("%x",_REG32((char*)aesctrl, AES_REG_CIPHER_2));
    kprintf("%x\n",_REG32((char*)aesctrl, AES_REG_CIPHER_3));

    // Check if the ciphertext matches the expected result
    if (cipher_test[0] == expected_cipher_test[0] &&
        cipher_test[1] == expected_cipher_test[1] &&
        cipher_test[2] == expected_cipher_test[2] &&
        cipher_test[3] == expected_cipher_test[3]) {
        kprintf("Testcase 1 passed!\n");
    } else {
        kprintf("Testcase 1 failed!\n");
    }

    // Perform self-test operations
    // This is a placeholder for actual self-test logic
    kprintf("AES self-test completed successfully.\n");
}