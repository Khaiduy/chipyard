package chipyard.crypto.poly

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


case class PolyParams
(
  address: BigInt,
  impl: Int = 0,
  nbits: Int = 14
) {
  require(nbits == 14, "TODO: This Poly does not support nbits different than 14")
}

case object PolyKey extends Field[Option[PolyParams]](None)

class poly_core extends BlackBox with HasBlackBoxResource {
    override def desiredName = "poly1305_core"
    val io = IO(new Bundle {
      //Inputs
      val clk           = Input(Clock())
      val reset_n       = Input(Bool())
      val init          = Input(Bool())
      val next          = Input(Bool())
      val finish        = Input(Bool())
      val key           = Input(UInt(256.W))
      val block         = Input(UInt(128.W))
      val blocklen      = Input(UInt(5.W))
      //Outputs
      val mac           = Output(UInt(128.W))
      val ready         = Output(Bool())
    })
    // add wrapper/blackbox after it is pre-processed
    addResource("/crypto-vsrc/poly1305.preprocessed.v")
}

class POLYTL(params: PolyParams, beatBytes: Int)(implicit p: Parameters) extends ClockSinkDomain(ClockSinkParameters())(p){
    val device = new SimpleDevice("poly", Seq("sifive,poly"))
    val node = TLRegisterNode(Seq(AddressSet(params.address, 0xFFF)), device, "reg/control", beatBytes=beatBytes)

    override lazy val module = new PolyImpl
    class PolyImpl extends Impl {
        withClockAndReset(clock, reset){
            // Key Registers
            val key_0        = RegInit(0.U(32.W))
            val key_1        = RegInit(0.U(32.W))
            val key_2        = RegInit(0.U(32.W))
            val key_3        = RegInit(0.U(32.W))
            val key_4        = RegInit(0.U(32.W))
            val key_5        = RegInit(0.U(32.W))
            val key_6        = RegInit(0.U(32.W))
            val key_7        = RegInit(0.U(32.W))

            // Block Registers
            val block_0        = RegInit(0.U(32.W))
            val block_1        = RegInit(0.U(32.W))
            val block_2        = RegInit(0.U(32.W))
            val block_3        = RegInit(0.U(32.W))

            // Block_len Registers
            val block_len      = RegInit(0.U(5.W))

            // Mac Registers
            val mac_0        = RegInit(0.U(32.W))
            val mac_1        = RegInit(0.U(32.W))
            val mac_2        = RegInit(0.U(32.W))
            val mac_3        = RegInit(0.U(32.W))

            // control Registers
            val init        = WireInit(false.B)
            val next        = WireInit(false.B)
            val finish      = WireInit(false.B)
            val reset_n     = RegInit(true.B)
            val ready       = RegInit(false.B)

            // Crypto-Core
            val poly_core = Module(new(poly_core))
            poly_core.io.reset_n := reset_n
            poly_core.io.init    := init
            poly_core.io.reset_n := reset_n
            poly_core.io.next    := next
            poly_core.io.blocklen:= block_len
            poly_core.io.clk     := clock
            poly_core.io.finish  := finish
            poly_core.io.block   := Cat(block_0,block_1,block_2,block_3)
            poly_core.io.key     := Cat(key_0,key_1,key_2,key_3,key_4,key_5,key_6,key_7)
            ready                := poly_core.io.ready
            mac_0                := poly_core.io.mac(127,96)
            mac_1                := poly_core.io.mac(95,64)
            mac_2                := poly_core.io.mac(63,32)
            mac_3                := poly_core.io.mac(31,0)

            // Tpoly register mapping
            node.regmap(
                PolyRegs.key_0 -> Seq(
                    RegField(32, key_0, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.key_1 -> Seq(
                    RegField(32, key_1, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.key_2 -> Seq(
                    RegField(32, key_2, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.key_3 -> Seq(
                    RegField(32, key_3, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.key_4 -> Seq(
                    RegField(32, key_4, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.key_5 -> Seq(
                    RegField(32, key_5, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.key_6 -> Seq(
                    RegField(32, key_6, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.key_7 -> Seq(
                    RegField(32, key_7, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.block_0 -> Seq(
                    RegField(32, block_0, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.block_1 -> Seq(
                    RegField(32, block_1, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.block_2 -> Seq(
                    RegField(32, block_2, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.block_3 -> Seq(
                    RegField(32, block_3, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.block_len -> Seq(
                    RegField(5, block_len, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.mac_0 -> Seq(
                    RegField.r(32, mac_0, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.mac_1 -> Seq(
                    RegField.r(32, mac_1, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.mac_2 -> Seq(
                    RegField.r(32, mac_2, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.mac_3 -> Seq(
                    RegField.r(32, mac_3, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.init -> Seq(
                    RegField(1, init, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.next -> Seq(
                    RegField(1, next, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.finish -> Seq(
                    RegField(1, finish, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.reset_n -> Seq(
                    RegField(1, reset_n, RegFieldDesc("write_data", "Tpoly write data"))
                ),
                PolyRegs.ready -> Seq(
                    RegField.r(1, ready, RegFieldDesc("write_data", "Tpoly write data"))
                )
            )
        }
    }
}

object POLYID {
    val nextId = {
        var i = -1; () => {
            i += 1; i
        }
    }
}

trait CanHavePeripheryPOLY { this: BaseSubsystem =>
    private val portName = s"poly_${POLYID.nextId()}"
    private val pbus = locateTLBusWrapper(PBUS)

    val poly_busy = p(PolyKey) match {
        case Some(params) => {
            val poly = LazyModule(new POLYTL(params, pbus.beatBytes)(p))
            poly.suggestName(portName)
            
            poly.clockNode := pbus.fixedClockNode
            pbus.coupleTo(portName) {poly.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

            poly
        }
        case None => None
        }
}

class WithPOLY(address: BigInt) extends Config((site, here, up) => {
  case PolyKey => {
    println(f"Setting POLY address: 0x${address}%X")
    Some(PolyParams(address = address))
  }
})
