package chipyard.crypto.trng
import chisel3._
import chisel3.util._

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

// declare params
case class TRNGParams(
    address: BigInt = 0x5000,
    asic_impl: Boolean = false, // true for ASIC, false for FPGA
    useXDC: Boolean = true // true for FPGA, false for ASIC
){
    require(if (asic_impl) useXDC == false else true, "ASIC implementation should not use XDC constraints")
}

// declare trait to be called in a system
case object TRNGKey extends Field[Option[TRNGParams]](None)

class TRNGIO() extends Bundle {
//   val iClk = Input(Clock())
  val iRst = Input(Bool())
  val iEn = Input(Bool())
  val iDelay = Input(UInt(32.W))
  val iNext = Input(Bool())
  val oValid = Output(Bool())
  val oRand = Output(UInt(32.W))
}

class TRNGMMIOModule(val asic_impl: Boolean, val useXDC: Boolean) extends Module {
    println(s"TRNGMMIOModule: asic_impl = $asic_impl, useXDC = $useXDC")

    val io = IO(new TRNGIO())

    /* TODO: implement the core here */
    var injectList = List(16, 19, 22, 25, 28)
    var feedbackSrc = List(29, 26, 23, 20, 18)
    var feedbackDst = List(2, 5, 7, 10, 13)

    val rg = Module(new RingGenerator(32, 5, injectList, feedbackSrc, feedbackDst, asic_impl=asic_impl, useXDC=useXDC))
    val ro = Module(new RingOscillator(4, asic_impl=asic_impl,useXDC=useXDC))

    // //Dummy for testing error Analog
    // val rg_bit = RegInit(0.U(1.W))
    // rg_bit := rg.io.o_bit
    // rg.io.i_inject := RegInit(0.U(1.W))
    // rg.io.i_rst := io.iRst
    // ro.io.i_en := io.iEn

    // io.oRand := RegInit(1.U(32.W))
    // io.oValid := RegInit(0.U(1.W))
    // rg.io.i_en := RegInit(0.U(1.W))

    // Ring Generator
    val rg_bit = WireDefault(0.U(1.W))
    rg_bit := rg.io.o_bit
    rg.io.i_inject := ro.io.o_out
    rg.io.i_rst := io.iRst
    ro.io.i_en := io.iEn

    //delay counter - initial wait time for calibration
    val tick = RegInit(false.B)
    val delayCnt = RegInit(0.U(32.W))

    when(io.iRst){
    delayCnt := 0.U
    tick := false.B
    }.otherwise{
    when(io.iEn && !tick) {
        delayCnt := delayCnt + 1.U
        when(delayCnt === io.iDelay) {
        tick := true.B
        }.otherwise{
        tick := tick
        }
    }.otherwise{
        delayCnt := delayCnt
        tick := tick
    }
    }

    val shiftReg = RegInit(0.U(32.W))
    val collectCnt = RegInit(0.U(5.W))
    val valid = RegInit(false.B)
    val ready = RegInit(true.B)

    def risingedge(x: Bool) = x && !RegNext(x)
    val nextTrigger = risingedge(io.iNext)

    when(io.iRst || nextTrigger){ //restart sampling when reset or ready to sample
    collectCnt := 0.U //reset counter when sampling is disable and restart another sampling
    valid := false.B // reset valid when not sampling
    shiftReg := 0.U
    }.otherwise{
    when(tick && !valid) {
        shiftReg := (shiftReg(30, 0) ## (rg_bit))
        collectCnt := collectCnt + 1.U
        when(collectCnt === 31.U) { //change here 2b
        valid := true.B //valid read data
        }.otherwise{
        valid := valid
        }
    }.otherwise{
        collectCnt := collectCnt
    }
    }

    io.oRand := Mux(valid, shiftReg, 0.U)
    io.oValid := valid
    rg.io.i_en := (io.iEn) & ((tick === false.B) || (valid === false.B))
}

object TRNGCtrlRegs {
    val control     = 0x00
    val status      = 0x04
    val delay       = 0x08
    val random      = 0x0C
}


class TRNGTL(params: TRNGParams, beatBytes: Int)(implicit p: Parameters) extends ClockSinkDomain(ClockSinkParameters())(p){
    val device = new SimpleDevice("trng", Seq("sifive,trng"))
    val node = TLRegisterNode(Seq(AddressSet(params.address, 4096-1)), device, "reg/control", beatBytes=beatBytes)

    override lazy val module = new TRNGImpl
    class TRNGImpl extends Impl {
        withClockAndReset(clock, reset){
            // declare inputs
            val rst    = RegInit(false.B)
            val enable = RegInit(false.B)
            val next   = RegInit(false.B)
            val delay  = RegInit(0.U(32.W))
            // declare outputs
            val valid  = Wire(Bool())
            val rand = Wire(UInt(32.W))
            
            // actual TRNG module
            val impl = Module(new TRNGMMIOModule(asic_impl= params.asic_impl, useXDC = params.useXDC))

            // connection
            impl.io.iRst   := reset.asBool || rst
            impl.io.iEn    := enable
            impl.io.iNext  := next
            impl.io.iDelay := delay

            valid  := impl.io.oValid
            rand := impl.io.oRand

            node.regmap(
                TRNGCtrlRegs.control -> Seq(
                    RegField(1, enable, RegFieldDesc("trigger", "TRNG enable")),
                    RegField(1, next, RegFieldDesc("trigger", "TRNG next")),
                    RegField(6),
                    RegField(1, rst, RegFieldDesc("rst", "TRNG reset", reset = Some(0)))
                ),
                TRNGCtrlRegs.status -> Seq(
                    RegField.r(1, valid, RegFieldDesc("valid", "TRNG data valid", volatile = true))
                ),
                TRNGCtrlRegs.delay -> Seq(RegField(32, delay, RegFieldDesc("delay", "delay time for calibrartion TRNG"))),
                TRNGCtrlRegs.random -> Seq(RegField(32, rand, RegFieldDesc("random", "random output for TRNG", volatile = true))),
            )
        }
    }
}

// this will auto +1 ID if there are many TRNG modules
object TRNGID {
  val nextId = {
    var i = -1; () => {
      i += 1; i
    }
  }
}

trait CanHavePeripheryTRNG { this: BaseSubsystem => 
    private val portName = s"trng_${TRNGID.nextId()}" //Modify this to numerate multiple trng module
    private val pbus = locateTLBusWrapper(PBUS)

    // val params = TRNGParams(p(TRNGKey).get.address)
    // val trng = LazyModule(new TRNGTL(params, pbus.beatBytes)(p))
    // trng.suggestName(portName)

    // trng.clockNode := pbus.fixedClockNode
    // pbus.coupleTo(portName) {trng.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

    // trng


    //This code handles the case when no TRNG is used
    val trng_busy = p(TRNGKey) match {
        case Some(params) => {
            val trng = LazyModule(new TRNGTL(params, pbus.beatBytes)(p))
            trng.suggestName(portName)

            trng.clockNode := pbus.fixedClockNode
            pbus.coupleTo(portName) {trng.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

            trng
        }
        case None => None
    }
    
}

class WithTRNG(address: BigInt, asic_impl: Boolean = false, useXDC: Boolean = true) extends Config((site, here, up) => {
    case TRNGKey => {
        println(f"Setting TRNG address: 0x${address}%X")
        assert(!asic_impl || !useXDC, "ASIC implementation should not use XDC constraints")
        Some(TRNGParams(address = address, asic_impl = asic_impl, useXDC = useXDC))
    }
})

