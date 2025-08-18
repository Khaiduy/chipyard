package chipyard.crypto.aes

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


case class AESParams
(
  address: BigInt,
  version: Int = 1,
) {
}

case object AESKey extends Field[Option[AESParams]](None)

class AES128 extends BlackBox with HasBlackBoxResource {
    override def desiredName: String = "AES128"
    val io = IO(new Bundle {
        val i_clk = Input(Clock())
        val i_rst = Input(Bool())
        val i_init = Input(Bool())
        val i_mode = Input(Bool())
        val i_enc = Input(Bool())
        val i_key_AES = Input(UInt(128.W))
        val i_msg_AES = Input(UInt(128.W))
        val o_cipher_AES = Output(UInt(128.W))
        val o_finish = Output(Bool())
    })

    addResource("/crypto-vsrc/aes128.preprocessed.v")
}

class AESTL(params: AESParams, beatBytes: Int)(implicit p: Parameters) extends ClockSinkDomain(ClockSinkParameters())(p){
    val device = new SimpleDevice("aes", Seq("sifive,aes-0.1"))
    val node = TLRegisterNode(Seq(AddressSet(params.address, 4096-1)), device, "reg/control", beatBytes=beatBytes)

    override lazy val module = new aesImpl
    class aesImpl extends Impl {
        withClockAndReset(clock, reset){
            //Registers
            val r_rst = RegInit(true.B)
            val w_init = WireInit(false.B)
            val w_mode = WireInit(false.B)
            val w_enc = WireInit(false.B)
            
            val key_0 = RegInit(0.U(32.W))
            val key_1 = RegInit(0.U(32.W))
            val key_2 = RegInit(0.U(32.W))
            val key_3 = RegInit(0.U(32.W))

            val msg_0 = RegInit(0.U(32.W))
            val msg_1 = RegInit(0.U(32.W))
            val msg_2 = RegInit(0.U(32.W))
            val msg_3 = RegInit(0.U(32.W))

            val cipher_0 = RegInit(0.U(32.W))
            val cipher_1 = RegInit(0.U(32.W))
            val cipher_2 = RegInit(0.U(32.W))
            val cipher_3 = RegInit(0.U(32.W))
            
            val o_finish = RegInit(false.B)

            //Core
            val core_aes = Module(new AES128())
            core_aes.io.i_clk := clock
            core_aes.io.i_rst := r_rst
            core_aes.io.i_init := w_init
            core_aes.io.i_mode := w_mode
            core_aes.io.i_enc := w_enc
            core_aes.io.i_key_AES := Cat(key_3, key_2, key_1, key_0)
            core_aes.io.i_msg_AES := Cat(msg_3, msg_2, msg_1, msg_0)

            cipher_0 := core_aes.io.o_cipher_AES(127, 96)
            cipher_1 := core_aes.io.o_cipher_AES(95, 64)
            cipher_2 := core_aes.io.o_cipher_AES(63, 32)
            cipher_3 := core_aes.io.o_cipher_AES(31, 0)
            o_finish := core_aes.io.o_finish

            // Register mapping
            node.regmap(
                AESRegs.rst_core -> Seq(RegField(1, r_rst, RegFieldDesc("rst_core", "Reset core", reset=Some(0)))),
                AESRegs.init -> Seq(RegField(1, w_init, RegFieldDesc("init", "Initialize core"))),
                AESRegs.mode -> Seq(RegField(1, w_mode, RegFieldDesc("mode", "Mode: 0 for ECB, 1 for CBC"))),
                AESRegs.enc -> Seq(RegField(1, w_enc, RegFieldDesc("enc", "Encryption: 0 for decryption, 1 for encryption"))),
                AESRegs.key_AES_0 -> Seq(RegField(32, key_0, RegFieldDesc("key_AES_0", "AES Key part 0"))),
                AESRegs.key_AES_1 -> Seq(RegField(32, key_1, RegFieldDesc("key_AES_1", "AES Key part 1"))),
                AESRegs.key_AES_2 -> Seq(RegField(32, key_2, RegFieldDesc("key_AES_2", "AES Key part 2"))),
                AESRegs.key_AES_3 -> Seq(RegField(32, key_3, RegFieldDesc("key_AES_3", "AES Key part 3"))),
                AESRegs.msg_AES_0 -> Seq(RegField(32, msg_0, RegFieldDesc("msg_AES_0", "Message part 0"))),
                AESRegs.msg_AES_1 -> Seq(RegField(32, msg_1, RegFieldDesc("msg_AES_1", "Message part 1"))),
                AESRegs.msg_AES_2 -> Seq(RegField(32, msg_2, RegFieldDesc("msg_AES_2", "Message part 2"))),
                AESRegs.msg_AES_3 -> Seq(RegField(32, msg_3, RegFieldDesc("msg_AES_3", "Message part 3"))),
                AESRegs.cipher_AES_0 -> Seq(RegField(32, cipher_0, RegFieldDesc("cipher_AES_0", "Cipher text part 0"))),
                AESRegs.cipher_AES_1 -> Seq(RegField(32, cipher_1, RegFieldDesc("cipher_AES_1", "Cipher text part 1"))),
                AESRegs.cipher_AES_2 -> Seq(RegField(32, cipher_2, RegFieldDesc("cipher_AES_2", "Cipher text part 2"))),
                AESRegs.cipher_AES_3 -> Seq(RegField(32, cipher_3, RegFieldDesc("cipher_AES_3", "Cipher text part 3"))),
                AESRegs.finish -> Seq(RegField(1, o_finish, RegFieldDesc("finish", "Finish signal, indicates operation completion")))
            )
        }
    }
}

object AESID{
    val nextId = {
        var i = -1; () => {
            i +=1; i
        }
    }
}

trait CanHavePeripheryAES {this: BaseSubsystem => 
    private val portName = s"aes_${AESID.nextId()}"
    private val pbus = locateTLBusWrapper(PBUS)

    val aes_busy = p(AESKey) match {
        case Some(params) => {
            val aes = LazyModule(new AESTL(params, pbus.beatBytes))
            aes.suggestName(portName)

            aes.clockNode := pbus.fixedClockNode
            pbus.coupleTo(portName) {aes.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

            aes
        }
        case None => None
    }
}

class WithAES(address: BigInt) extends Config((site, here, up) => {
  case AESKey => {
    println(f"Setting AES address: 0x${address}%X")
    Some(AESParams(address = address))
  }
})