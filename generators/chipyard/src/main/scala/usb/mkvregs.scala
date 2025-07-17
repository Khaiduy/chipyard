package chipyard.usb.mkv

object MKVCtrlRegs {
  val key1 = 0x00
  val key2 = 0x20
  val idata_key1 = 0x40
  val idata_key2 = 0x60
  val odata = 0x80
  val config = 0xA0 //9bit
  val regstatus = 0xC0
  val control_reg= 0x100
}