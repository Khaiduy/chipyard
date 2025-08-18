package chipyard.crypto.aes_gcm

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


case class AESGCMParams
(
  address: BigInt,
  version: Int = 1,
) {
}

case object AESGCMKey extends Field[Option[AESGCMParams]](None)

class aes_gcm_core extends BlackBox with HasBlackBoxResource {
    override def desiredName: String = "aes_gcm_v4_TOP"
    val io = IO(new Bundle {
      val ICLK = Input(Clock())
      val IRSTN= Input(Bool())
      val ICTRL= Input(UInt(4.W))
      val OREADY= Output(Bool())

      val IIV= Input(UInt(96.W))
      val IIV_VALID= Input(Bool())
      val IKEY=Input(UInt(256.W))
      val IKEY_VALID= Input(Bool())
      val IKEYLEN= Input(Bool())

      val IAAD=Input(UInt(128.W))
      val IAAD_VALID= Input(Bool())

      val IBLOCK=Input(UInt(128.W))
      val IBLOCK_VALID= Input(Bool())

      val ITAG = Input(UInt(128.W))
      val ITAG_VALID= Input(Bool())

      val ORESULT=Output(UInt(128.W))
      val ORESULT_VALID=Output(Bool())
      val OTAG=Output(UInt(128.W))
      val OTAG_VALID=Output(Bool())
      val OAUTHENTIC=Output(Bool())
    })
    addResource("/crypto-vsrc/aes_gcm_small.preprocessed.v")
}

class AESGCMTL(params: AESGCMParams, beatBytes: Int)(implicit p: Parameters) extends ClockSinkDomain(ClockSinkParameters())(p){
    val device = new SimpleDevice("aesgcm", Seq("sifive,aesgcm-0.1"))
    val node = TLRegisterNode(Seq(AddressSet(params.address, 4096-1)), device, "reg/control", beatBytes=beatBytes)

    override lazy val module = new aesgcmImpl
    class aesgcmImpl extends Impl {
        withClockAndReset(clock, reset){
            //Registers
            val ICTRL= RegInit(0.U(4.W))
            val OREADY= WireDefault(0.U(1.W))

            val IIV_0= RegInit(0.U(32.W))
            val IIV_1= RegInit(0.U(32.W))
            val IIV_2= RegInit(0.U(32.W))
            val IIV_VALID= RegInit(0.U(1.W))
            val IKEY_0=RegInit(0.U(32.W))
            val IKEY_1=RegInit(0.U(32.W))
            val IKEY_2=RegInit(0.U(32.W))
            val IKEY_3=RegInit(0.U(32.W))
            val IKEY_4=RegInit(0.U(32.W))
            val IKEY_5=RegInit(0.U(32.W))
            val IKEY_6=RegInit(0.U(32.W))
            val IKEY_7=RegInit(0.U(32.W))
            val IKEY_VALID= RegInit(0.U(1.W))
            val IKEYLEN= RegInit(0.U(1.W))

            //130 pins
            val IAAD_0=RegInit(0.U(32.W))
            val IAAD_1=RegInit(0.U(32.W))
            val IAAD_2=RegInit(0.U(32.W))
            val IAAD_3=RegInit(0.U(32.W))
            val IAAD_VALID= RegInit(0.U(1.W))

            val IBLOCK_0=RegInit(0.U(32.W))
            val IBLOCK_1=RegInit(0.U(32.W))
            val IBLOCK_2=RegInit(0.U(32.W))
            val IBLOCK_3=RegInit(0.U(32.W))
            val IBLOCK_VALID= RegInit(0.U(1.W))

            val ITAG_0 = RegInit(0.U(32.W))
            val ITAG_1 = RegInit(0.U(32.W))
            val ITAG_2 = RegInit(0.U(32.W))
            val ITAG_3 = RegInit(0.U(32.W))
            val ITAG_VALID= RegInit(0.U(1.W))
            val IRESETN= RegInit(1.U(1.W))

            val ORESULT_0=WireDefault(0.U(32.W))
            val ORESULT_1=WireDefault(0.U(32.W))
            val ORESULT_2=WireDefault(0.U(32.W))
            val ORESULT_3=WireDefault(0.U(32.W))
            val ORESULT_VALID=WireDefault(0.U(1.W))
            val OTAG_0=WireDefault(0.U(32.W))
            val OTAG_1=WireDefault(0.U(32.W))
            val OTAG_2=WireDefault(0.U(32.W))
            val OTAG_3=WireDefault(0.U(32.W))
            val OTAG_VALID=WireDefault(0.U(1.W))
            val OAUTHENTIC=WireDefault(0.U(1.W))

            val core_aes_gcm = Module(new aes_gcm_core)
            core_aes_gcm.io.ICLK     := clock
            core_aes_gcm.io.IRSTN := !reset.asBool & IRESETN //TODO: need to come from a register?

            core_aes_gcm.io.ICTRL     := ICTRL
            OREADY := core_aes_gcm.io.OREADY

            core_aes_gcm.io.IIV    := Cat(IIV_0,IIV_1,IIV_2)
            core_aes_gcm.io.IIV_VALID    := IIV_VALID
            core_aes_gcm.io.IKEY  := Cat(IKEY_0,IKEY_1,IKEY_2,IKEY_3,IKEY_4,IKEY_5,IKEY_6,IKEY_7)
            core_aes_gcm.io.IKEY_VALID  := IKEY_VALID
            core_aes_gcm.io.IKEYLEN  := IKEYLEN

            core_aes_gcm.io.IAAD  := Cat(IAAD_0,IAAD_1,IAAD_2,IAAD_3)
            core_aes_gcm.io.IAAD_VALID  := IAAD_VALID
            core_aes_gcm.io.IBLOCK  := Cat(IBLOCK_0,IBLOCK_1,IBLOCK_2,IBLOCK_3)
            core_aes_gcm.io.IBLOCK_VALID  := IBLOCK_VALID

            core_aes_gcm.io.ITAG  := Cat(ITAG_0,ITAG_1,ITAG_2,ITAG_3)
            core_aes_gcm.io.ITAG_VALID  := ITAG_VALID

            ORESULT_3                 := core_aes_gcm.io.ORESULT(31,0)
            ORESULT_2                 := core_aes_gcm.io.ORESULT(63,32)
            ORESULT_1                 := core_aes_gcm.io.ORESULT(95,64)
            ORESULT_0                 := core_aes_gcm.io.ORESULT(127,96)
            ORESULT_VALID                 := core_aes_gcm.io.ORESULT_VALID
            OTAG_3                 := core_aes_gcm.io.OTAG(31,0)
            OTAG_2                 := core_aes_gcm.io.OTAG(63,32)
            OTAG_1                 := core_aes_gcm.io.OTAG(95,64)
            OTAG_0                 := core_aes_gcm.io.OTAG(127,96)
            OTAG_VALID                 := core_aes_gcm.io.OTAG_VALID
            OAUTHENTIC                 := core_aes_gcm.io.OAUTHENTIC

            // Register mapping
            node.regmap(
              AES_GCMRegs.ICTRL -> Seq(
                RegField(4, ICTRL, RegFieldDesc("IINIT", " "))
              ),
              AES_GCMRegs.OREADY -> Seq(
                RegField.r(1, OREADY, RegFieldDesc("OREADY", " "))
              ),
              AES_GCMRegs.IIV_0 -> Seq(
                RegField(32, IIV_0, RegFieldDesc("IIV_0", " "))
              ),
              AES_GCMRegs.IIV_1 -> Seq(
                RegField(32, IIV_1, RegFieldDesc("IIV_1", " "))
              ),
              AES_GCMRegs.IIV_2 -> Seq(
                RegField(32, IIV_2, RegFieldDesc("IIV_2", " "))
              ),
              AES_GCMRegs.IIV_VALID -> Seq(
                RegField(1, IIV_VALID, RegFieldDesc("IIV_VALID", " "))
              ),
              AES_GCMRegs.IKEY_0 -> Seq(
                RegField(32, IKEY_0, RegFieldDesc("IKEY_0", " "))
              ),
              AES_GCMRegs.IKEY_1 -> Seq(
                RegField(32, IKEY_1, RegFieldDesc("IKEY_1", " "))
              ),
              AES_GCMRegs.IKEY_2 -> Seq(
                RegField(32, IKEY_2, RegFieldDesc("IKEY_2", " "))
              ),
              AES_GCMRegs.IKEY_3 -> Seq(
                RegField(32, IKEY_3, RegFieldDesc("IKEY_3", " "))
              ),
              AES_GCMRegs.IKEY_4 -> Seq(
                RegField(32, IKEY_4, RegFieldDesc("IKEY_4", " "))
              ),
              AES_GCMRegs.IKEY_5 -> Seq(
                RegField(32, IKEY_5, RegFieldDesc("IKEY_5", " "))
              ),
              AES_GCMRegs.IKEY_6 -> Seq(
                RegField(32, IKEY_6, RegFieldDesc("IKEY_6", " "))
              ),
              AES_GCMRegs.IKEY_7 -> Seq(
                RegField(32, IKEY_7, RegFieldDesc("IKEY_7", " "))
              ),
              AES_GCMRegs.IKEY_VALID -> Seq(
                RegField(1, IKEY_VALID, RegFieldDesc("IKEY_VALID", " "))
              ),
              AES_GCMRegs.IKEYLEN -> Seq(
                RegField(1, IKEYLEN, RegFieldDesc("IKEYLEN", " "))
              ),
              AES_GCMRegs.IAAD_0 -> Seq(
                RegField(32, IAAD_0, RegFieldDesc("IAAD_0", " ", reset = Some(0)))
              ),
              AES_GCMRegs.IAAD_1 -> Seq(
                RegField(32, IAAD_1, RegFieldDesc("IAAD_1", " ", reset = Some(0)))
              ),
              AES_GCMRegs.IAAD_2 -> Seq(
                RegField(32, IAAD_2, RegFieldDesc("IAAD_2", " ", reset = Some(0)))
              ),
              AES_GCMRegs.IAAD_3 -> Seq(
                RegField(32, IAAD_3, RegFieldDesc("IAAD_3", " ", reset = Some(0)))
              ),
              AES_GCMRegs.IAAD_VALID -> Seq(
                RegField(1, IAAD_VALID, RegFieldDesc("IAAD_VALID", " ", volatile = true))
              ),
              AES_GCMRegs.IBLOCK_0 -> Seq(
                RegField(32, IBLOCK_0, RegFieldDesc("IBLOCK_0", " ", volatile = true))
              ),
              AES_GCMRegs.IBLOCK_1 -> Seq(
                RegField(32, IBLOCK_1, RegFieldDesc("IBLOCK_1", " ", volatile = true))
              ),
              AES_GCMRegs.IBLOCK_2 -> Seq(
                RegField(32, IBLOCK_2, RegFieldDesc("IBLOCK_2", " ", volatile = true))
              ),
              AES_GCMRegs.IBLOCK_3 -> Seq(
                RegField(32, IBLOCK_3, RegFieldDesc("IBLOCK_3", " ", volatile = true))
              ),
              AES_GCMRegs.IBLOCK_VALID -> Seq(
                RegField(1, IBLOCK_VALID, RegFieldDesc("IBLOCK_VALID", " ", volatile = true))
              ),
              AES_GCMRegs.ITAG_0 -> Seq(
                RegField(32, ITAG_0, RegFieldDesc("ITAG_0", " ", volatile = true))
              ),
              AES_GCMRegs.ITAG_1 -> Seq(
                RegField(32, ITAG_1, RegFieldDesc("ITAG_1", " ", volatile = true))
              ),
              AES_GCMRegs.ITAG_2 -> Seq(
                RegField(32, ITAG_2, RegFieldDesc("ITAG_2", " ", volatile = true))
              ),
              AES_GCMRegs.ITAG_3 -> Seq(
                RegField(32, ITAG_3, RegFieldDesc("ITAG_3", " ", volatile = true))
              ),
              AES_GCMRegs.ITAG_VALID -> Seq(
                RegField(1, ITAG_VALID, RegFieldDesc("ITAG_VALID", " ", volatile = true))
              ),
              AES_GCMRegs.ORESULT_0 -> Seq(
                RegField.r(32, ORESULT_0, RegFieldDesc("ORESULT_0", " ", volatile = true))
              ),
              AES_GCMRegs.ORESULT_1 -> Seq(
                RegField.r(32, ORESULT_1, RegFieldDesc("ORESULT_1", " ", volatile = true))
              ),
              AES_GCMRegs.ORESULT_2 -> Seq(
                RegField.r(32, ORESULT_2, RegFieldDesc("ORESULT_2", " ", volatile = true))
              ),
              AES_GCMRegs.ORESULT_3 -> Seq(
                RegField.r(32, ORESULT_3, RegFieldDesc("ORESULT_3", " ", volatile = true))
              ),
              AES_GCMRegs.ORESULT_VALID -> Seq(
                RegField.r(32, ORESULT_VALID, RegFieldDesc("ORESULT_VALID", " ", volatile = true))
              ),
              AES_GCMRegs.OTAG_0 -> Seq(
                RegField.r(32, OTAG_0, RegFieldDesc("OTAG_0", " ", volatile = true))
              ),
              AES_GCMRegs.OTAG_1 -> Seq(
                RegField.r(32, OTAG_1, RegFieldDesc("OTAG_1", " ", volatile = true))
              ),
              AES_GCMRegs.OTAG_2 -> Seq(
                RegField.r(32, OTAG_2, RegFieldDesc("OTAG_2", " ", volatile = true))
              ),
              AES_GCMRegs.OTAG_3 -> Seq(
                RegField.r(32, OTAG_3, RegFieldDesc("OTAG_3", " ", volatile = true))
              ),
              AES_GCMRegs.OTAG_VALID -> Seq(
                RegField.r(1, OTAG_VALID, RegFieldDesc("OTAG_VALID", " ", volatile = true))
              ),
              AES_GCMRegs.OAUTHENTIC -> Seq(
                RegField.r(1, OAUTHENTIC, RegFieldDesc("OAUTHENTIC", " ", volatile = true))
              ),
              AES_GCMRegs.IRESETN -> Seq(
                RegField(1, IRESETN, RegFieldDesc("IRESET", " ", volatile = true))
              )
            )
        }
    }
}

object AESGCMID{
    val nextId = {
        var i = -1; () => {
            i +=1; i
        }
    }
}

trait CanHavePeripheryAESGCM {this: BaseSubsystem =>
    private val portName = s"aes_${AESGCMID.nextId()}"
    private val pbus = locateTLBusWrapper(PBUS)

    val aes_busy = p(AESGCMKey) match {
        case Some(params) => {
            val aesgcm = LazyModule(new AESGCMTL(params, pbus.beatBytes))
            aesgcm.suggestName(portName)

            aesgcm.clockNode := pbus.fixedClockNode
            pbus.coupleTo(portName) {aesgcm.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

            aesgcm
        }
        case None => None
    }
}

class WithAESGCM(address: BigInt) extends Config((site, here, up) => {
  case AESGCMKey => {
    println(f"Setting AES-GCM address: 0x${address}%X")
    Some(AESGCMParams(address = address))
  }
})