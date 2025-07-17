package chipyard.usb.mkv

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
import os.write.over

case class MKVParams
(
    address: BigInt,
    version: Int = 1,
){}

case object MKVKeys extends Field[Option[MKVParams]](None)

class mkv extends BlackBox with HasBlackBoxResource {
    override def desiredName = "mkv"
    val io = IO(new Bundle {
    // Inputs
    val clk               = Input(Clock())
    val reset             = Input(Bool())
    val enc0_dec1         = Input(Bool())
    val keylen            = Input(UInt(2.W))
    val ecb               = Input(Bool())
    val key1              = Input(UInt(256.W))
    val key2              = Input(UInt(256.W))
    val key1_start        = Input(Bool())
    val key2_start        = Input(Bool())
    val idata_key1_valid  = Input(Bool())
    val idata_key1        = Input(UInt(128.W))
    val j_block           = Input(UInt(5.W))
    val idata_key2_valid  = Input(Bool())
    val idata_key2        = Input(UInt(128.W))

    // Outputs
    val okey1_ready       = Output(Bool())
    val okey2_ready       = Output(Bool())
    val odata             = Output(UInt(128.W))
    val o_data_valid      = Output(Bool())
    val key2_enc_done     = Output(Bool())
    })

  // add wrapper/blackbox after it is pre-processed
  addResource("/usb-vsrc/mkv_xts_ecb.v")
}

class MKVTL(params: MKVParams, beatBytes: Int)(implicit p: Parameters) extends ClockSinkDomain(ClockSinkParameters())(p){
    val device = new SimpleDevice("mkv", Seq("sifive,mkv-0.1"))
    val node = TLRegisterNode(Seq(AddressSet(params.address, 4096-1)), device, "reg/control", beatBytes=beatBytes)

    override lazy val module = new mkvImpl
    class mkvImpl extends Impl {
        withClockAndReset(clock, reset){
            // Reset
            val r_rst = RegInit(true.B)

            // Data
            val key1 = Reg(Vec(8, UInt(32.W)))
            val key2 = Reg(Vec(8, UInt(32.W)))
            val idata_key1 = Reg(Vec(4, UInt(32.W)))
            val idata_key2 = Reg(Vec(4, UInt(32.W)))
            val j_block = Reg(UInt(5.W))
            val odata = Wire(UInt(128.W))

            // Configurations
            val enc0_dec1 = RegInit(false.B)
            val keylen = Reg(UInt(2.W))
            val ecb = WireInit(false.B)

            // Triggers
            val key1_start = WireInit(false.B)
            val key2_start = WireInit(false.B)
            val idata_key1_valid = WireInit(false.B)
            val idata_key2_valid = WireInit(false.B)
            val okey1_ready = Wire(Bool())
            val okey2_ready = Wire(Bool())
            val o_data_valid = Wire(Bool())
            val key2_enc_done = Wire(Bool())

            // Instantiate the mkv blackbox
            val mkv_inst = Module(new mkv)
            mkv_inst.io.clk := clock
            mkv_inst.io.reset := r_rst // reset.asBool() - change to register control instead of system reset
            
            // mkv_inst.io.idata_key1 := (for(i <- 0 until 16) yield idata_key1.asUInt()((1+i)*8-1, (0+i)*8)).reduce(Cat(_,_))
            // mkv_inst.io.key1 := (for(i <- 0 until 32) yield key1.asUInt()((1+i)*8-1, (0+i)*8)).reduce(Cat(_,_))
            // mkv_inst.io.idata_key2 := (for(i <- 0 until 16) yield idata_key2.asUInt()((1+i)*8-1, (0+i)*8)).reduce(Cat(_,_))
            // mkv_inst.io.key2 := (for(i <- 0 until 32) yield key2.asUInt()((1+i)*8-1, (0+i)*8)).reduce(Cat(_,_))

            mkv_inst.io.idata_key1 := Cat(idata_key1.reverse)
            mkv_inst.io.key1 := Cat(key1.reverse)
            mkv_inst.io.idata_key2 := Cat(idata_key2.reverse)
            mkv_inst.io.key2 := Cat(key2.reverse)

            mkv_inst.io.j_block := j_block
            o_data_valid := mkv_inst.io.o_data_valid
            key2_enc_done := mkv_inst.io.key2_enc_done
            mkv_inst.io.ecb := ecb
            odata := mkv_inst.io.odata
            mkv_inst.io.enc0_dec1 := enc0_dec1
            mkv_inst.io.keylen := keylen
            mkv_inst.io.key1_start := key1_start
            mkv_inst.io.key2_start := key2_start
            mkv_inst.io.idata_key1_valid := idata_key1_valid
            mkv_inst.io.idata_key2_valid := idata_key2_valid
            okey1_ready := mkv_inst.io.okey1_ready
            okey2_ready := mkv_inst.io.okey2_ready
            o_data_valid:= mkv_inst.io.o_data_valid


            // Regfields - map these control register to memory map
            val idata_key1_regmap: Seq[RegField] = idata_key1.map{ i => RegField(32, i) }
            val idata_key2_regmap: Seq[RegField] = idata_key2.map{ i => RegField(32, i) }
            val key1_regmap: Seq[RegField] = key1.map{ i => RegField(32, i) }
            val key2_regmap: Seq[RegField] = key2.map{ i => RegField(32, i) }
            //val j_block_regmap: Seq[RegField] = j_block.map{ i => RegField(32, i) }
            val odata_regmap: Seq[RegField] = for(i <- 0 until 16) yield RegField.r(8, odata((16-i)*8-1, (15-i)*8))
            val config_regmap: Seq[RegField] = Seq(
                RegField(1, enc0_dec1, RegFieldDesc("enc0_dec1", "Encode / Decode", reset = Some(0))),
                RegField(2, keylen),
                RegField(1, ecb),
                RegField(5, j_block)
            )

            val reg_and_status = Seq(
                RegField(1, key1_start, RegFieldDesc("key1_start", "Key1 Expansion Enable", reset = Some(0))),
                RegField(1, key2_start, RegFieldDesc("key2_start", "Key2 Expansion Enable", reset = Some(0))),
                RegField(1, idata_key1_valid, RegFieldDesc("idata_key1_valid", "Data_key1 Enable", reset = Some(0))),
                RegField(1, idata_key2_valid, RegFieldDesc("idata_key2_valid", "Data_key2 Enable", reset = Some(0))),
                RegField.r(1, okey1_ready, RegFieldDesc("okey1_ready", "okey1_ready", volatile = true)),
                RegField.r(1, okey2_ready, RegFieldDesc("okey2_ready", "okey2_ready", volatile = true)),
                RegField.r(1, key2_enc_done, RegFieldDesc("key2_enc_done", "key2_enc_done", volatile = true)),
                RegField.r(1, o_data_valid, RegFieldDesc("o_data_valid", "o_data_valid", volatile = true))
            )

            val control_reg: Seq[RegField] = Seq(
                RegField(1, r_rst, RegFieldDesc("reset", "Reset the MKV module", reset = Some(0))),
            )

            node.regmap(
                MKVCtrlRegs.key1 -> key1_regmap,
                MKVCtrlRegs.key2 -> key2_regmap,
                MKVCtrlRegs.idata_key1 -> idata_key1_regmap,
                MKVCtrlRegs.idata_key2 -> idata_key2_regmap,
                MKVCtrlRegs.odata -> odata_regmap,
                MKVCtrlRegs.config -> config_regmap,
                MKVCtrlRegs.regstatus -> reg_and_status,
                MKVCtrlRegs.control_reg -> control_reg
            )
        }
    }
}


object MKVID{
    val nextId = {
        var i = -1; () => {
            i += 1; i
        }
    }
}

trait CanHavePeripheryMKV { this: BaseSubsystem =>
  private val portName = s"mkv_${MKVID.nextId()}"
  private val pbus = locateTLBusWrapper(PBUS)

  val mkv_busy = p(MKVKeys) match  {
    case Some(params) => {
        val mkv = LazyModule(new MKVTL(params, pbus.beatBytes))
        mkv.suggestName(portName)

        mkv.clockNode := pbus.fixedClockNode
        pbus.coupleTo(portName) {mkv.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

        mkv
    }
    case None => None
  }
}

class WithMKV(address: BigInt) extends Config((site, here, up) => {
    case MKVKeys => {
        println(f"Setting MKV address: 0x${address}%X")
        Some(MKVParams(address = address))
    }
})