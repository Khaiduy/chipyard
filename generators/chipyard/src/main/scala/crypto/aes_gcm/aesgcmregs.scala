package chipyard.crypto.aes_gcm

object AES_GCMRegs {
  val ICTRL  = 0x100
  val OREADY= 0x104

  val IIV_0    = 0x110
  val IIV_1    = 0x114
  val IIV_2    = 0x118
  val IIV_VALID= 0x11C
  val IKEY_0   = 0x120
  val IKEY_1   = 0x124
  val IKEY_2   = 0x128
  val IKEY_3   = 0x12C
  val IKEY_4   = 0x130
  val IKEY_5   = 0x134
  val IKEY_6   = 0x138
  val IKEY_7   = 0x13C
  val IKEY_VALID= 0x140
  val IKEYLEN= 0x144
  val IAAD_0   = 0x148
  val IAAD_1   = 0x14C
  val IAAD_2   = 0x150
  val IAAD_3   = 0x154
  val IAAD_VALID= 0x158

  val IBLOCK_0 =0x160
  val IBLOCK_1 =0x164
  val IBLOCK_2 =0x168
  val IBLOCK_3 =0x16C
  val IBLOCK_VALID= 0x170

  val ITAG_0   = 0x178
  val ITAG_1   = 0x17C
  val ITAG_2   = 0x180
  val ITAG_3   = 0x184
  val ITAG_VALID= 0x188
  val ORESULT_0=0x18C
  val ORESULT_1=0x190
  val ORESULT_2=0x194
  val ORESULT_3=0x198
  val ORESULT_VALID=0x19C
  val OTAG_0   =0x1A0
  val OTAG_1   =0x1A4
  val OTAG_2   =0x1A8
  val OTAG_3   =0x1AC
  val OTAG_VALID=0x1B0
  val OAUTHENTIC=0x1B4
  val IRESETN = 0x1B8
}
