package chipyard.crypto.aes

object AESRegs {
    val rst_core        = 0x00
    val init            = 0x04
    val mode            = 0x08
    val enc             = 0x0C
    val key_AES_0       = 0x10
    val key_AES_1       = 0x14
    val key_AES_2       = 0x18
    val key_AES_3       = 0x1C
    val msg_AES_0       = 0x20
    val msg_AES_1       = 0x24
    val msg_AES_2       = 0x28
    val msg_AES_3       = 0x2C
    val cipher_AES_0    = 0x30
    val cipher_AES_1    = 0x34
    val cipher_AES_2    = 0x38
    val cipher_AES_3    = 0x3C
    val finish          = 0x40
}