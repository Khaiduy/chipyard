package chipyard.crypto.ecdsa

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

case class ECDSAParams
(
  address: BigInt,
  version: Int = 1,
) {
}

case object ECDSAKey extends Field[Option[ECDSAParams]](None)

class ecdsa_core extends BlackBox with HasBlackBoxResource {
    override def desiredName = "ecdsa_block"
    val io = IO(new Bundle {
    val clk = Input(Clock())
    //Gen point
    val in_gen_point_reset= Input(Bool())
    val in_point_x= Input(UInt(256.W))
    val in_point_y= Input(UInt(256.W))
    val in_S= Input(UInt(256.W))
    val out_point_x= Output(UInt(256.W))
    val out_point_y= Output(UInt(256.W))
    val done_point=  Output(Bool())
    //modInv
    val in_modInv_reset= Input(Bool())
    val in_modInv= Input(UInt(256.W))
    val out_modInv= Output(UInt(256.W))
    val done_modInv =  Output(Bool())
    //multmod
    val in_reset_modmult= Input(Bool())
    val in_a_modmult= Input(UInt(256.W))
    val  in_b_modmult= Input(UInt(256.W))
    val done_modmult= Output(Bool())
    val  out_modmult= Output(UInt(256.W))
    //add point a != b
    val in_reset_add= Input(Bool())
    val in_p_x= Input(UInt(256.W))
    val in_p_y= Input(UInt(256.W))
    val in_q_x=Input(UInt(256.W))
    val in_q_y= Input(UInt(256.W))
    val done_add= Output(Bool())
    val out_r_x= Output(UInt(256.W))
    val out_r_y= Output(UInt(256.W))
    })
    // add wrapper/blackbox after it is pre-processed
    addResource("/crypto-vsrc/ecdsa_block_v1.preprocessed.sv")
}

class ECDSATL(params: ECDSAParams, beatBytes: Int)(implicit p: Parameters) extends ClockSinkDomain(ClockSinkParameters())(p){
    val device = new SimpleDevice("ecdsa", Seq("sifive,ecdsa"))
    val node = TLRegisterNode(Seq(AddressSet(params.address, 0xFFF)), device, "reg/control", beatBytes=beatBytes)

    override lazy val module = new ECDSAImpl
    class ECDSAImpl extends Impl {
        withClockAndReset(clock, reset){
            val in_gen_point_reset = RegInit(true.B)
            val in_point_x = RegInit(VecInit(Seq.fill(8)(0.U(32.W))))
            val in_point_y = RegInit(VecInit(Seq.fill(8)(0.U(32.W))))
            val in_S= RegInit(VecInit(Seq.fill(8)(0.U(32.W))))
            val out_point_x= VecInit(Seq.fill(8)(WireDefault(0.U(32.W))))
            val out_point_y= VecInit(Seq.fill(8)(WireDefault(0.U(32.W))))
            val done_point=  WireDefault(false.B)
            //modInv
            val in_modInv_reset= RegInit(true.B)
            val in_modInv= RegInit(VecInit(Seq.fill(8)(0.U(32.W))))
            val out_modInv= VecInit(Seq.fill(8)(WireDefault(0.U(32.W))))
            val done_modInv =  WireDefault(false.B)
            //multmod
            val in_reset_modmult= RegInit(true.B)
            val in_a_modmult= RegInit(VecInit(Seq.fill(8)(0.U(32.W))))
            val in_b_modmult= RegInit(VecInit(Seq.fill(8)(0.U(32.W))))
            val done_modmult= WireDefault(false.B)
            val out_modmult= VecInit(Seq.fill(8)(WireDefault(0.U(32.W))))
            //add point a != b
            val in_reset_add= RegInit(true.B)
            val in_p_x= RegInit(VecInit(Seq.fill(8)(0.U(32.W))))
            val in_p_y= RegInit(VecInit(Seq.fill(8)(0.U(32.W))))
            val in_q_x=RegInit(VecInit(Seq.fill(8)(0.U(32.W))))
            val in_q_y= RegInit(VecInit(Seq.fill(8)(0.U(32.W))))
            val done_add= WireDefault(false.B)
            val out_r_x= VecInit(Seq.fill(8)(WireDefault(0.U(32.W))))
            val out_r_y= VecInit(Seq.fill(8)(WireDefault(0.U(32.W))))

            println("Core ECDSA implemented")
            val core_ecdsa_block = Module(new ecdsa_core)
            core_ecdsa_block.io.clk     := clock
            core_ecdsa_block.io.in_gen_point_reset := in_gen_point_reset
            core_ecdsa_block.io.in_point_x := in_point_x.asUInt.asTypeOf(UInt(256.W))
            core_ecdsa_block.io.in_point_y := in_point_y.asUInt.asTypeOf(UInt(256.W))
            core_ecdsa_block.io.in_S := in_S.asUInt.asTypeOf(UInt(256.W))
            for(i <- 0 until 8) {
                out_point_x(i)   :=core_ecdsa_block.io.out_point_x((32+i*32)-1,i*32)
                out_point_y(i)   :=core_ecdsa_block.io.out_point_y((32+i*32)-1,i*32)
            }
            done_point      :=core_ecdsa_block.io.done_point
            //modInv
            core_ecdsa_block.io.in_modInv_reset := in_modInv_reset
            core_ecdsa_block.io.in_modInv    := in_modInv.asUInt.asTypeOf(UInt(256.W))
            for(i <- 0 until 8) {
                out_modInv(i) :=core_ecdsa_block.io.out_modInv((32+i*32)-1,i*32)
            }
            done_modInv :=core_ecdsa_block.io.done_modInv
            //multmod
            core_ecdsa_block.io.in_reset_modmult :=in_reset_modmult
            core_ecdsa_block.io.in_a_modmult    :=in_a_modmult.asUInt.asTypeOf(UInt(256.W))
            core_ecdsa_block.io.in_b_modmult   :=in_b_modmult.asUInt.asTypeOf(UInt(256.W))
            for(i <- 0 until 8) {
                out_modmult(i) :=core_ecdsa_block.io.out_modmult((32+i*32)-1,i*32)
            }
            done_modmult :=core_ecdsa_block.io.done_modmult
            //add point a !                           
            core_ecdsa_block.io.in_reset_add :=in_reset_add
            core_ecdsa_block.io.in_p_x:=in_p_x.asUInt.asTypeOf(UInt(256.W))
            core_ecdsa_block.io.in_p_y :=in_p_y.asUInt.asTypeOf(UInt(256.W))
            core_ecdsa_block.io.in_q_x  :=in_q_x.asUInt.asTypeOf(UInt(256.W))
            core_ecdsa_block.io.in_q_y :=in_q_y.asUInt.asTypeOf(UInt(256.W))
            done_add   :=  core_ecdsa_block.io.done_add
            for(i <- 0 until 8) {
                out_r_x(i) :=core_ecdsa_block.io.out_r_x((32+i*32)-1,i*32)
                out_r_y(i) :=core_ecdsa_block.io.out_r_y((32+i*32)-1,i*32)
            }

            node.regmap(
                ECDSA_BLOCKRegs.IN_GEN_POINT_RESET -> Seq(
                    RegField(1, in_gen_point_reset, RegFieldDesc("IN_GEN_POINT_RESET", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_X_0 -> Seq(
                    RegField(32, in_point_x(0), RegFieldDesc("IN_POINT_X_0", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_X_1 -> Seq(
                    RegField(32, in_point_x(1), RegFieldDesc("IN_POINT_X_1", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_X_2 -> Seq(
                    RegField(32, in_point_x(2), RegFieldDesc("IN_POINT_X_2", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_X_3 -> Seq(
                    RegField(32, in_point_x(3), RegFieldDesc("IN_POINT_X_3", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_X_4 -> Seq(
                    RegField(32, in_point_x(4), RegFieldDesc("IN_POINT_X_4", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_X_5 -> Seq(
                    RegField(32, in_point_x(5), RegFieldDesc("IN_POINT_X_5", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_X_6 -> Seq(
                    RegField(32, in_point_x(6), RegFieldDesc("IN_POINT_X_6", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_X_7 -> Seq(
                    RegField(32, in_point_x(7), RegFieldDesc("IN_POINT_X_7", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_Y_0 -> Seq(
                    RegField(32, in_point_y(0), RegFieldDesc("IN_POINT_Y_0", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_Y_1 -> Seq(
                    RegField(32, in_point_y(1), RegFieldDesc("IN_POINT_Y_1", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_Y_2 -> Seq(
                    RegField(32, in_point_y(2), RegFieldDesc("IN_POINT_Y_2", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_Y_3 -> Seq(
                    RegField(32, in_point_y(3), RegFieldDesc("IN_POINT_Y_3", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_Y_4 -> Seq(
                    RegField(32, in_point_y(4), RegFieldDesc("IN_POINT_Y_4", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_Y_5 -> Seq(
                    RegField(32, in_point_y(5), RegFieldDesc("IN_POINT_Y_5", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_Y_6 -> Seq(
                    RegField(32, in_point_y(6), RegFieldDesc("IN_POINT_Y_6", " "))
                ),
                ECDSA_BLOCKRegs.IN_POINT_Y_7 -> Seq(
                    RegField(32, in_point_y(7), RegFieldDesc("IN_POINT_Y_7", " "))
                ),
                ECDSA_BLOCKRegs.IN_S_0 -> Seq(
                    RegField(32, in_S(0), RegFieldDesc("IN_S_0", " "))
                ),
                ECDSA_BLOCKRegs.IN_S_1 -> Seq(
                    RegField(32, in_S(1), RegFieldDesc("IN_S_1", " "))
                ),
                ECDSA_BLOCKRegs.IN_S_2 -> Seq(
                    RegField(32, in_S(2), RegFieldDesc("IN_S_2", " "))
                ),
                ECDSA_BLOCKRegs.IN_S_3 -> Seq(
                    RegField(32, in_S(3), RegFieldDesc("IN_S_3", " "))
                ),
                ECDSA_BLOCKRegs.IN_S_4 -> Seq(
                    RegField(32, in_S(4), RegFieldDesc("IN_S_4", " "))
                ),
                ECDSA_BLOCKRegs.IN_S_5 -> Seq(
                    RegField(32, in_S(5), RegFieldDesc("IN_S_5", " "))
                ),
                ECDSA_BLOCKRegs.IN_S_6 -> Seq(
                    RegField(32, in_S(6), RegFieldDesc("IN_S_6", " "))
                ),
                ECDSA_BLOCKRegs.IN_S_7 -> Seq(
                    RegField(32, in_S(7), RegFieldDesc("IN_S_7", " "))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_X_0 -> Seq(
                    RegField.r(32, out_point_x(0), RegFieldDesc("OUT_POINT_X_0", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_X_1 -> Seq(
                    RegField.r(32, out_point_x(1), RegFieldDesc("OUT_POINT_X_1", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_X_2 -> Seq(
                    RegField.r(32, out_point_x(2), RegFieldDesc("OUT_POINT_X_2", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_X_3 -> Seq(
                    RegField.r(32, out_point_x(3), RegFieldDesc("OUT_POINT_X_3", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_X_4 -> Seq(
                    RegField.r(32, out_point_x(4), RegFieldDesc("OUT_POINT_X_4", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_X_5 -> Seq(
                    RegField.r(32, out_point_x(5), RegFieldDesc("OUT_POINT_X_5", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_X_6 -> Seq(
                    RegField.r(32, out_point_x(6), RegFieldDesc("OUT_POINT_X_6", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_X_7 -> Seq(
                    RegField.r(32, out_point_x(7), RegFieldDesc("OUT_POINT_X_7", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_Y_0 -> Seq(
                    RegField.r(32, out_point_y(0), RegFieldDesc("OUT_POINT_Y_0", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_Y_1 -> Seq(
                    RegField.r(32, out_point_y(1), RegFieldDesc("OUT_POINT_Y_1", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_Y_2 -> Seq(
                    RegField.r(32, out_point_y(2), RegFieldDesc("OUT_POINT_Y_2", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_Y_3 -> Seq(
                    RegField.r(32, out_point_y(3), RegFieldDesc("OUT_POINT_Y_3", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_Y_4 -> Seq(
                    RegField.r(32, out_point_y(4), RegFieldDesc("OUT_POINT_Y_4", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_Y_5 -> Seq(
                    RegField.r(32, out_point_y(5), RegFieldDesc("OUT_POINT_Y_5", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_Y_6 -> Seq(
                    RegField.r(32, out_point_y(6), RegFieldDesc("OUT_POINT_Y_6", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_POINT_Y_7 -> Seq(
                    RegField.r(32, out_point_y(7), RegFieldDesc("OUT_POINT_Y_7", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.DONE_POINT -> Seq(
                    RegField.r(1, done_point, RegFieldDesc("DONE_POINT", " ", volatile = true))
                ),//MODINV
                ECDSA_BLOCKRegs.IN_MODINV_RESET -> Seq(
                    RegField(1, in_modInv_reset, RegFieldDesc("IN_MODINV_RESET", " "))
                ),
                ECDSA_BLOCKRegs.OUT_MODINV_0 -> Seq(
                    RegField.r(32, out_modInv(0), RegFieldDesc("OUT_MODINV_0", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODINV_1 -> Seq(
                    RegField.r(32, out_modInv(1), RegFieldDesc("OUT_MODINV_1", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODINV_2 -> Seq(
                    RegField.r(32, out_modInv(2), RegFieldDesc("OUT_MODINV_2", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODINV_3 -> Seq(
                    RegField.r(32, out_modInv(3), RegFieldDesc("OUT_MODINV_3", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODINV_4 -> Seq(
                    RegField.r(32, out_modInv(4), RegFieldDesc("OUT_MODINV_4", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODINV_5 -> Seq(
                    RegField.r(32, out_modInv(5), RegFieldDesc("OUT_MODINV_5", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODINV_6 -> Seq(
                    RegField.r(32, out_modInv(6), RegFieldDesc("OUT_MODINV_6", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODINV_7 -> Seq(
                    RegField.r(32, out_modInv(7), RegFieldDesc("OUT_MODINV_7", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.IN_MODINV_0 -> Seq(
                    RegField(32, in_modInv(0), RegFieldDesc("IN_MODINV_0", " "))
                ),
                ECDSA_BLOCKRegs.IN_MODINV_1 -> Seq(
                    RegField(32, in_modInv(1), RegFieldDesc("IN_MODINV_1", " "))
                ),
                ECDSA_BLOCKRegs.IN_MODINV_2 -> Seq(
                    RegField(32, in_modInv(2), RegFieldDesc("IN_MODINV_2", " "))
                ),
                ECDSA_BLOCKRegs.IN_MODINV_3 -> Seq(
                    RegField(32, in_modInv(3), RegFieldDesc("IN_MODINV_3", " "))
                ),
                ECDSA_BLOCKRegs.IN_MODINV_4 -> Seq(
                    RegField(32, in_modInv(4), RegFieldDesc("IN_MODINV_4", " "))
                ),
                ECDSA_BLOCKRegs.IN_MODINV_5 -> Seq(
                    RegField(32, in_modInv(5), RegFieldDesc("IN_MODINV_5", " "))
                ),
                ECDSA_BLOCKRegs.IN_MODINV_6 -> Seq(
                    RegField(32, in_modInv(6), RegFieldDesc("IN_MODINV_6", " "))
                ),
                ECDSA_BLOCKRegs.IN_MODINV_7 -> Seq(
                    RegField(32, in_modInv(7), RegFieldDesc("IN_MODINV_7", " "))
                ),
                ECDSA_BLOCKRegs.IN_RESET_MODMULT -> Seq(
                    RegField(1, in_reset_modmult, RegFieldDesc("IN_RESET_MODMULT", " "))
                ),
                ECDSA_BLOCKRegs.DONE_MODINV -> Seq(
                    RegField.r(1, done_modInv, RegFieldDesc("DONE_MODINV", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODMULT_0 -> Seq(
                    RegField.r(32, out_modmult(0), RegFieldDesc("OUT_MODMULT_0", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODMULT_1 -> Seq(
                    RegField.r(32, out_modmult(1), RegFieldDesc("OUT_MODMULT_1", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODMULT_2 -> Seq(
                    RegField.r(32, out_modmult(2), RegFieldDesc("OUT_MODMULT_2", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODMULT_3 -> Seq(
                    RegField.r(32, out_modmult(3), RegFieldDesc("OUT_MODMULT_3", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODMULT_4 -> Seq(
                    RegField.r(32, out_modmult(4), RegFieldDesc("OUT_MODMULT_4", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODMULT_5 -> Seq(
                    RegField.r(32, out_modmult(5), RegFieldDesc("OUT_MODMULT_5", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODMULT_6 -> Seq(
                    RegField.r(32, out_modmult(6), RegFieldDesc("OUT_MODMULT_6", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_MODMULT_7 -> Seq(
                    RegField.r(32, out_modmult(7), RegFieldDesc("OUT_MODMULT_7", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.IN_A_MODMULT_0 -> Seq(
                    RegField(32, in_a_modmult(0), RegFieldDesc("IN_A_MODMULT_0", " "))
                ),
                ECDSA_BLOCKRegs.IN_A_MODMULT_1 -> Seq(
                    RegField(32, in_a_modmult(1), RegFieldDesc("IN_A_MODMULT_1", " "))
                ),
                ECDSA_BLOCKRegs.IN_A_MODMULT_2 -> Seq(
                    RegField(32, in_a_modmult(2), RegFieldDesc("IN_A_MODMULT_2", " "))
                ),
                ECDSA_BLOCKRegs.IN_A_MODMULT_3 -> Seq(
                    RegField(32, in_a_modmult(3), RegFieldDesc("IN_A_MODMULT_3", " "))
                ),
                ECDSA_BLOCKRegs.IN_A_MODMULT_4 -> Seq(
                    RegField(32, in_a_modmult(4), RegFieldDesc("IN_A_MODMULT_4", " "))
                ),
                ECDSA_BLOCKRegs.IN_A_MODMULT_5 -> Seq(
                    RegField(32, in_a_modmult(5), RegFieldDesc("IN_A_MODMULT_5", " "))
                ),
                ECDSA_BLOCKRegs.IN_A_MODMULT_6 -> Seq(
                    RegField(32, in_a_modmult(6), RegFieldDesc("IN_A_MODMULT_6", " "))
                ),
                ECDSA_BLOCKRegs.IN_A_MODMULT_7 -> Seq(
                    RegField(32, in_a_modmult(7), RegFieldDesc("IN_A_MODMULT_7", " "))
                ),
                ECDSA_BLOCKRegs.IN_B_MODMULT_0 -> Seq(
                    RegField(32, in_b_modmult(0), RegFieldDesc("IN_B_MODMULT_0", " "))
                ),
                ECDSA_BLOCKRegs.IN_B_MODMULT_1 -> Seq(
                    RegField(32, in_b_modmult(1), RegFieldDesc("IN_B_MODMULT_1", " "))
                ),
                ECDSA_BLOCKRegs.IN_B_MODMULT_2 -> Seq(
                    RegField(32, in_b_modmult(2), RegFieldDesc("IN_B_MODMULT_2", " "))
                ),
                ECDSA_BLOCKRegs.IN_B_MODMULT_3 -> Seq(
                    RegField(32, in_b_modmult(3), RegFieldDesc("IN_B_MODMULT_3", " "))
                ),
                ECDSA_BLOCKRegs.IN_B_MODMULT_4 -> Seq(
                    RegField(32, in_b_modmult(4), RegFieldDesc("IN_B_MODMULT_4", " "))
                ),
                ECDSA_BLOCKRegs.IN_B_MODMULT_5 -> Seq(
                    RegField(32, in_b_modmult(5), RegFieldDesc("IN_B_MODMULT_5", " "))
                ),
                ECDSA_BLOCKRegs.IN_B_MODMULT_6 -> Seq(
                    RegField(32, in_b_modmult(6), RegFieldDesc("IN_B_MODMULT_6", " "))
                ),
                ECDSA_BLOCKRegs.IN_B_MODMULT_7 -> Seq(
                    RegField(32, in_b_modmult(7), RegFieldDesc("IN_B_MODMULT_7", " "))
                ),
                ECDSA_BLOCKRegs.DONE_MODMULT -> Seq(
                    RegField.r(1, done_modmult, RegFieldDesc("DONE_MODMULT", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.IN_RESET_ADD -> Seq(
                    RegField(1, in_reset_add, RegFieldDesc("IN_RESET_ADD", " "))
                ),
                ECDSA_BLOCKRegs.DONE_ADD -> Seq(
                    RegField.r(1, done_add, RegFieldDesc("DONE_ADD", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.IN_Q_X_0 -> Seq(
                    RegField(32, in_q_x(0), RegFieldDesc("IN_Q_X_0", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_X_1 -> Seq(
                    RegField(32, in_q_x(1), RegFieldDesc("IN_Q_X_1", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_X_2 -> Seq(
                    RegField(32, in_q_x(2), RegFieldDesc("IN_Q_X_2", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_X_3 -> Seq(
                    RegField(32, in_q_x(3), RegFieldDesc("IN_Q_X_3", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_X_4 -> Seq(
                    RegField(32, in_q_x(4), RegFieldDesc("IN_Q_X_4", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_X_5 -> Seq(
                    RegField(32, in_q_x(5), RegFieldDesc("IN_Q_X_5", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_X_6 -> Seq(
                    RegField(32, in_q_x(6), RegFieldDesc("IN_Q_X_6", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_X_7 -> Seq(
                    RegField(32, in_q_x(7), RegFieldDesc("IN_Q_X_7", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_Y_0 -> Seq(
                    RegField(32, in_q_y(0), RegFieldDesc("IN_Q_Y_0", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_Y_1 -> Seq(
                    RegField(32, in_q_y(1), RegFieldDesc("IN_Q_Y_1", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_Y_2 -> Seq(
                    RegField(32, in_q_y(2), RegFieldDesc("IN_Q_Y_2", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_Y_3 -> Seq(
                    RegField(32, in_q_y(3), RegFieldDesc("IN_Q_Y_3", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_Y_4 -> Seq(
                    RegField(32, in_q_y(4), RegFieldDesc("IN_Q_Y_4", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_Y_5 -> Seq(
                    RegField(32, in_q_y(5), RegFieldDesc("IN_Q_Y_5", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_Y_6 -> Seq(
                    RegField(32, in_q_y(6), RegFieldDesc("IN_Q_Y_6", " "))
                ),
                ECDSA_BLOCKRegs.IN_Q_Y_7 -> Seq(
                    RegField(32, in_q_y(7), RegFieldDesc("IN_Q_Y_7", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_X_0 -> Seq(
                    RegField(32, in_p_x(0), RegFieldDesc("IN_P_X_0", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_X_1 -> Seq(
                    RegField(32, in_p_x(1), RegFieldDesc("IN_P_X_1", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_X_2 -> Seq(
                    RegField(32, in_p_x(2), RegFieldDesc("IN_P_X_2", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_X_3 -> Seq(
                    RegField(32, in_p_x(3), RegFieldDesc("IN_P_X_3", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_X_4 -> Seq(
                    RegField(32, in_p_x(4), RegFieldDesc("IN_P_X_4", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_X_5 -> Seq(
                    RegField(32, in_p_x(5), RegFieldDesc("IN_P_X_5", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_X_6 -> Seq(
                    RegField(32, in_p_x(6), RegFieldDesc("IN_P_X_6", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_X_7 -> Seq(
                    RegField(32, in_p_x(7), RegFieldDesc("IN_P_X_7", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_Y_0 -> Seq(
                    RegField(32, in_p_y(0), RegFieldDesc("IN_P_Y_0", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_Y_1 -> Seq(
                    RegField(32, in_p_y(1), RegFieldDesc("IN_P_Y_1", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_Y_2 -> Seq(
                    RegField(32, in_p_y(2), RegFieldDesc("IN_P_Y_2", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_Y_3 -> Seq(
                    RegField(32, in_p_y(3), RegFieldDesc("IN_P_Y_3", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_Y_4 -> Seq(
                    RegField(32, in_p_y(4), RegFieldDesc("IN_P_Y_4", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_Y_5 -> Seq(
                    RegField(32, in_p_y(5), RegFieldDesc("IN_P_Y_5", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_Y_6 -> Seq(
                    RegField(32, in_p_y(6), RegFieldDesc("IN_P_Y_6", " "))
                ),
                ECDSA_BLOCKRegs.IN_P_Y_7 -> Seq(
                    RegField(32, in_p_y(7), RegFieldDesc("IN_P_Y_7", " "))
                ),
                ECDSA_BLOCKRegs.OUT_R_X_0 -> Seq(
                    RegField.r(32, out_r_x(0), RegFieldDesc("OUT_R_X_0", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_X_1 -> Seq(
                    RegField.r(32, out_r_x(1), RegFieldDesc("OUT_R_X_1", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_X_2 -> Seq(
                    RegField.r(32, out_r_x(2), RegFieldDesc("OUT_R_X_2", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_X_3 -> Seq(
                    RegField.r(32, out_r_x(3), RegFieldDesc("OUT_R_X_3", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_X_4 -> Seq(
                    RegField.r(32, out_r_x(4), RegFieldDesc("OUT_R_X_4", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_X_5 -> Seq(
                    RegField.r(32, out_r_x(5), RegFieldDesc("OUT_R_X_5", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_X_6 -> Seq(
                    RegField.r(32, out_r_x(6), RegFieldDesc("OUT_R_X_6", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_X_7 -> Seq(
                    RegField.r(32, out_r_x(7), RegFieldDesc("OUT_R_X_7", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_Y_0 -> Seq(
                    RegField.r(32, out_r_y(0), RegFieldDesc("OUT_R_Y_0", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_Y_1 -> Seq(
                    RegField.r(32, out_r_y(1), RegFieldDesc("OUT_R_Y_1", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_Y_2 -> Seq(
                    RegField.r(32, out_r_y(2), RegFieldDesc("OUT_R_Y_2", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_Y_3 -> Seq(
                    RegField.r(32, out_r_y(3), RegFieldDesc("OUT_R_Y_3", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_Y_4 -> Seq(
                    RegField.r(32, out_r_y(4), RegFieldDesc("OUT_R_Y_4", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_Y_5 -> Seq(
                    RegField.r(32, out_r_y(5), RegFieldDesc("OUT_R_Y_5", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_Y_6 -> Seq(
                    RegField.r(32, out_r_y(6), RegFieldDesc("OUT_R_Y_6", " ", volatile = true))
                ),
                ECDSA_BLOCKRegs.OUT_R_Y_7 -> Seq(
                    RegField.r(32, out_r_y(7), RegFieldDesc("OUT_R_Y_7", " ", volatile = true))
                ),
            )
        }
    }
}

object ECDSAID {
    val nextId = {
        var i = -1; () => {
            i += 1; i
        }
    }
}

trait CanHavePeripheryECDSA { this: BaseSubsystem => 
    private val portName = s"ecdsa_$ECDSAID.nextId()"
    private val pbus = locateTLBusWrapper(PBUS)

    val ecdsa_busy = p(ECDSAKey) match {
        case Some(params) => {
            val ecdsa = LazyModule(new ECDSATL(params, pbus.beatBytes)(p))
            ecdsa.suggestName(portName)

            ecdsa.clockNode := pbus.fixedClockNode
            pbus.coupleTo(portName) {ecdsa.node := TLFragmenter(pbus.beatBytes, pbus.blockBytes) := _ }

            ecdsa
        }
        case None => None
    }
}

class WithECDSA(address: BigInt) extends Config((site, here, up) => {
    case ECDSAKey => {
        println(f"Setting ECDSA address: 0x${address}%X")
        Some(ECDSAParams(address = address))
    }
})