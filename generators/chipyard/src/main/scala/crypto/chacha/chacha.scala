package chipyard.crypto.chacha


import chisel3._
import chisel3.util._
import chisel3.util.random._
import chisel3.util.HasBlackBoxResource

import org.chipsalliance.cde.config.{Field, Parameters, Config}
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.interrupts._
import freechips.rocketchip.interrupts.{IntXing, IntSourceNode, IntSinkNode, IntSourcePortSimple, IntSinkPortSimple}
import freechips.rocketchip.prci._
import freechips.rocketchip.regmapper._
import freechips.rocketchip.subsystem._
import freechips.rocketchip.tilelink._
import freechips.rocketchip.devices.tilelink._
import freechips.rocketchip.util._
import sifive.blocks.util.{DeviceParams,DeviceAttachParams}
import sifive.blocks.devices.pinctrl.{PinCtrl, Pin, BasePin, EnhancedPin, EnhancedPinCtrl}
import java.net.InetAddress



case class ChachaParams
(
  address: BigInt,
  impl: Int = 0,
  nbits: Int = 14
) {
  require(nbits == 14, "TODO: This Chacha does not support nbits different than 14")
}


case object ChachaKey extends Field[Option[ChachaParams]](None)


class chacha_core extends BlackBox with HasBlackBoxResource {
  override def desiredName = "chacha_core"
  val io = IO(new Bundle {
    //Inputs
    val clk             = Input(Clock())
    val reset_n         = Input(Bool())
    val init            = Input(Bool())
    val next            = Input(Bool())
    val key             = Input(UInt(256.W))
    val iv              = Input(UInt(96.W))
    val ctr             = Input(UInt(32.W))
    val data_in         = Input(UInt(512.W))
    //Outputs
    val ready           = Output(Bool())
    val data_out        = Output(UInt(512.W))
  })
  // add wrapper/blackbox after it is pre-processed
  addResource("/crypto-vsrc/chacha.preprocessed.v")
}


class CHACHATL(params: ChachaParams, beatBytes: Int)(implicit p: Parameters) extends ClockSinkDomain(ClockSinkParameters())(p){
    val device = new SimpleDevice("chacha", Seq("sifive,chacha"))
    val node = TLRegisterNode(Seq(AddressSet(params.address, 4096-1)), device, "reg/control", beatBytes=beatBytes)

    override lazy val module = new ChachaImpl
    class ChachaImpl extends Impl {
        withClockAndReset(clock, reset){
            // Registers
            val key_0        = RegInit(0.U(32.W))
            val key_1        = RegInit(0.U(32.W))
            val key_2        = RegInit(0.U(32.W))
            val key_3        = RegInit(0.U(32.W))
            val key_4        = RegInit(0.U(32.W))
            val key_5        = RegInit(0.U(32.W))
            val key_6        = RegInit(0.U(32.W))
            val key_7        = RegInit(0.U(32.W))

            val nonce_0      = RegInit(0.U(32.W))
            val nonce_1      = RegInit(0.U(32.W))
            val nonce_2      = RegInit(0.U(32.W))
            val b_counter    = RegInit(0.U(32.W))

            // status_in
            val in_0    = RegInit(0.U(32.W))
            val in_1    = RegInit(0.U(32.W))
            val in_2    = RegInit(0.U(32.W))
            val in_3    = RegInit(0.U(32.W))
            val in_4    = RegInit(0.U(32.W))
            val in_5    = RegInit(0.U(32.W))
            val in_6    = RegInit(0.U(32.W))
            val in_7    = RegInit(0.U(32.W))
            val in_8    = RegInit(0.U(32.W))
            val in_9    = RegInit(0.U(32.W))
            val in_10   = RegInit(0.U(32.W))
            val in_11   = RegInit(0.U(32.W))
            val in_12   = RegInit(0.U(32.W))
            val in_13   = RegInit(0.U(32.W))
            val in_14   = RegInit(0.U(32.W))
            val in_15   = RegInit(0.U(32.W))


            // status_out
            val out_0    = RegInit(0.U(32.W))
            val out_1    = RegInit(0.U(32.W))
            val out_2    = RegInit(0.U(32.W))
            val out_3    = RegInit(0.U(32.W))
            val out_4    = RegInit(0.U(32.W))
            val out_5    = RegInit(0.U(32.W))
            val out_6    = RegInit(0.U(32.W))
            val out_7    = RegInit(0.U(32.W))
            val out_8    = RegInit(0.U(32.W))
            val out_9    = RegInit(0.U(32.W))
            val out_10   = RegInit(0.U(32.W))
            val out_11   = RegInit(0.U(32.W))
            val out_12   = RegInit(0.U(32.W))
            val out_13   = RegInit(0.U(32.W))
            val out_14   = RegInit(0.U(32.W))
            val out_15   = RegInit(0.U(32.W))

            val rst_core_n  = RegInit(true.B)
            val init        = WireInit(false.B)
            val next        = WireInit(false.B)
            val ready       = RegInit(false.B)

            val core_chacha = Module(new chacha_core())
            core_chacha.io.key     := Cat(key_0,key_1,key_2,key_3,key_4,key_5,key_6,key_7)
            core_chacha.io.data_in := Cat(in_0,in_1,in_2,in_3,in_4,in_5,in_6,in_7,in_8,in_9,in_10,in_11,in_12,in_13,in_14,in_15)
            core_chacha.io.iv      := Cat(nonce_0,nonce_1,nonce_2)
            core_chacha.io.ctr     := b_counter
            core_chacha.io.clk     := clock
            core_chacha.io.reset_n := rst_core_n
            core_chacha.io.init    := init
            core_chacha.io.next    := next
            ready                  := core_chacha.io.ready
            out_15                 := core_chacha.io.data_out(31,0)
            out_14                 := core_chacha.io.data_out(63,32)
            out_13                 := core_chacha.io.data_out(95,64)
            out_12                 := core_chacha.io.data_out(127,96)
            out_11                 := core_chacha.io.data_out(159,128)
            out_10                 := core_chacha.io.data_out(191,160)
            out_9                  := core_chacha.io.data_out(223,192)
            out_8                  := core_chacha.io.data_out(255,224)
            out_7                  := core_chacha.io.data_out(287,256)
            out_6                  := core_chacha.io.data_out(319,288)
            out_5                  := core_chacha.io.data_out(351,320)
            out_4                  := core_chacha.io.data_out(383,352)
            out_3                  := core_chacha.io.data_out(415,384)
            out_2                  := core_chacha.io.data_out(447,416)
            out_1                  := core_chacha.io.data_out(479,448)
            out_0                  := core_chacha.io.data_out(511,480)

            // Tcha register mapping
            node.regmap(
                ChachaRegs.key_0 -> Seq(
                    RegField(32, key_0, RegFieldDesc("write_data", "Tcha write data"))
                ),
                ChachaRegs.key_1 -> Seq(
                    RegField(32, key_1, RegFieldDesc("write_data", "Tcha write data"))
                ),
                ChachaRegs.key_2 -> Seq(
                    RegField(32, key_2, RegFieldDesc("write_data", "Tcha write data"))
                ),
                ChachaRegs.key_3 -> Seq(
                    RegField(32, key_3, RegFieldDesc("write_data", "Tcha write data"))
                ),
                ChachaRegs.key_4 -> Seq(
                    RegField(32, key_4, RegFieldDesc("write_data", "Tcha write data"))
                ),
                ChachaRegs.key_5 -> Seq(
                    RegField(32, key_5, RegFieldDesc("write_data", "Tcha write data"))
                ),
                ChachaRegs.key_6 -> Seq(
                    RegField(32, key_6, RegFieldDesc("write_data", "Tcha write data"))
                ),
                ChachaRegs.key_7 -> Seq(
                    RegField(32, key_7, RegFieldDesc("write_data", "Tcha write data"))
                ),
                ChachaRegs.nonce_0 -> Seq(
                    RegField(32, nonce_0, RegFieldDesc("write_data", "Tcha write data"))
                ),
                ChachaRegs.nonce_1 -> Seq(
                    RegField(32, nonce_1, RegFieldDesc("write_data", "Tcha write data"))
                ),
                ChachaRegs.nonce_2 -> Seq(
                    RegField(32, nonce_2, RegFieldDesc("write_data", "Tcha write data"))
                ),
                ChachaRegs.block_counter -> Seq(
                    RegField(32, b_counter, RegFieldDesc("address", "Tcha address", reset = Some(0)))
                ),
                ChachaRegs.in_0 -> Seq(
                    RegField(32, in_0, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_1 -> Seq(
                    RegField(32, in_1, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_2 -> Seq(
                    RegField(32, in_2, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_3 -> Seq(
                    RegField(32, in_3, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_4 -> Seq(
                    RegField(32, in_4, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_5 -> Seq(
                    RegField(32, in_5, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_6 -> Seq(
                    RegField(32, in_6, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_7 -> Seq(
                    RegField(32, in_7, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_8 -> Seq(
                    RegField(32, in_8, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_9 -> Seq(
                    RegField(32, in_9, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_10 -> Seq(
                    RegField(32, in_10, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_11 -> Seq(
                    RegField(32, in_11, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_12 -> Seq(
                    RegField(32, in_12, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_13 -> Seq(
                    RegField(32, in_13, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_14 -> Seq(
                    RegField(32, in_14, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.in_15 -> Seq(
                    RegField(32, in_15, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.rst_core -> Seq(
                    RegField(1, rst_core_n, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.init -> Seq(
                    RegField(1, init, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.next -> Seq(
                    RegField(1, next, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.ready -> Seq(
                    RegField.r(1, ready, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_0 -> Seq(
                    RegField.r(32, out_0, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_1 -> Seq(
                    RegField.r(32, out_1, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_2 -> Seq(
                    RegField.r(32, out_2, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_3 -> Seq(
                    RegField.r(32, out_3, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_4 -> Seq(
                    RegField.r(32, out_4, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_5 -> Seq(
                    RegField.r(32, out_5, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_6 -> Seq(
                    RegField.r(32, out_6, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_7 -> Seq(
                    RegField.r(32, out_7, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_8 -> Seq(
                    RegField.r(32, out_8, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_9 -> Seq(
                    RegField.r(32, out_9, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_10 -> Seq(
                    RegField.r(32, out_10, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_11 -> Seq(
                    RegField.r(32, out_11, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_12 -> Seq(
                    RegField.r(32, out_12, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_13 -> Seq(
                    RegField.r(32, out_13, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_14 -> Seq(
                    RegField.r(32, out_14, RegFieldDesc("CS", "Tcha CS", volatile = true))
                ),
                ChachaRegs.out_15 -> Seq(
                    RegField.r(32, out_15, RegFieldDesc("CS", "Tcha CS", volatile = true))
                )
            )
        }
    }
}

object CHACHAID {
    val nextId = {
        var i = -1; () => {
            i += 1; i
        }
    }
}


trait CanHavePeripheryCHACHA { this: BaseSubsystem =>
  private val portName = s"chacha_${CHACHAID.nextId()}" //Modify this to numerate multiple chacha module
  private val pbus = locateTLBusWrapper(PBUS)


  val chacha_busy = p(ChachaKey) match {
    case Some(params) => {
      val chacha = LazyModule(new CHACHATL(params, pbus.beatBytes)(p))
      chacha.suggestName(portName)

      chacha.clockNode := pbus.fixedClockNode
      pbus.coupleTo(portName) {chacha.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

      chacha
    }
    case None => None   
  }  
}

class WithCHACHA(address: BigInt) extends Config((site, here, up) => {
    case ChachaKey => {
        println(f"Setting CHACHA address: 0x${address}%X")
        Some(ChachaParams(address = address))
    }
})