package ascon

import chisel3._
import freechips.rocketchip.tile.OpcodeSet

object OpcodeSet {
  def custom0 = new OpcodeSet(Seq("b0001011".U))
  def custom1 = new OpcodeSet(Seq("b0101011".U))
  def custom2 = new OpcodeSet(Seq("b1011011".U))
  def custom3 = new OpcodeSet(Seq("b1111011".U))
  def all = custom0 | custom1 | custom2 | custom3
}

object ISA {
  val READ  = "b0001011".U(7.W) // custom 0
  val WRITE = "b0101011".U(7.W) // custom 1
}
