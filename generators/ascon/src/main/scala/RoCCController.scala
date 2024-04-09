//see LICENSE for license
//authors: Duy
package ascon

import chisel3._

import scala.collection.mutable.HashMap
import scala.collection.mutable.ArrayBuffer
import scala.util.Random
import Chisel.ImplicitConversions._
import Chisel.{Bits, Bool, Cat, Enum, Reg, UInt, Vec, is, log2Ceil, log2Up, switch, when}
import chisel3.util._

import scala.collection.mutable.HashMap
import freechips.rocketchip.tile.{CoreParams, HasCoreParameters}
import freechips.rocketchip.rocket.constants.MemoryOpConstants
import org.chipsalliance.cde.config._

class ControllerDecouplerIO(xLen: Int = 32)(override implicit val p: Parameters) extends Bundle
  with HasCoreParameters
  with MemoryOpConstants {
  // Request
  val rocc_req_rs1      = Input(UInt(xLen.W))
  val rocc_req_rs2      = Input(UInt(xLen.W))
  val rocc_req_rd       = Input(UInt(5.W))
  val rocc_req_cmd      = Input(UInt(7.W))
  val rocc_req_funct    = Input(UInt(7.W))
  val rocc_req_valid    = Input(Bool())
  val rocc_req_ready    = Output(Bool())

  // Response
  val rocc_resp_rd      = Output(UInt(5.W))
  val rocc_resp_data    = Output(UInt(xLen.W))
  val rocc_resp_valid   = Output(Bool())

  val busy              = Output(Bool())
  val dmem_req_val      = Output(Bool())
  val dmem_req_rdy      = Input(Bool())
  val dmem_req_tag      = Output(UInt(coreParams.dcacheReqTagBits.W))
  val dmem_req_addr     = Output(UInt(coreMaxAddrBits.W))
  val dmem_req_cmd      = Output(UInt(5.W))
  val dmem_req_size     = Output(UInt(log2Ceil(coreDataBytes + 1).W))

  val dmem_resp_val     = Input(Bool())
  val dmem_resp_tag     = Input(UInt(7.W))
  val dmem_resp_data    = Input(UInt(xLen.W))

  val sfence            = Output(Bool())

}

class RoCCControllerIO (xLen: Int = 32)(implicit p: Parameters) extends Bundle {
  // Control signals
  val clock = Input(Clock())
  val reset = Input(UInt(1.W))

  // Controller-Decoupler interface
  val decoupler_io = new ControllerDecouplerIO(xLen)(p)

  // Black box interface
  val bb_io = Flipped(new myPermutation_bb_IO(xLen))
}

class RoCCController (override val xLen: Int)(override implicit val p: Parameters) extends Module
  with HasCoreParameters
  with MemoryOpConstants {

  val io = IO(new RoCCControllerIO(xLen)(p))




  //val req_rd          = Reg(chiselTypeOf(io.decoupler_io.rocc_resp_rd))

  val funct           = io.decoupler_io.rocc_req_funct
  val doWrite_0       = funct === 0.U
  val doWrite_1       = funct === 1.U
  val doWrite_2       = funct === 2.U
  val doWrite_3       = funct === 3.U
  val doWrite_4       = funct === 4.U
  val doWrite_rcon    = funct === 5.U

  val valid           = io.decoupler_io.rocc_req_valid
  val x0_in_reg       = Reg(UInt(64.W))
  val x1_in_reg       = Reg(UInt(64.W))
  val x2_in_reg       = Reg(UInt(64.W))
  val x3_in_reg       = Reg(UInt(64.W))
  val x4_in_reg       = Reg(UInt(64.W))
  val rcon_in_reg     = Reg(UInt(4.W))

  //NOTE: For ascon_state_t union
  //As rs1 and rs2 is 32 bits,
  //rs1 is the value of w[i][0] and rs2 is the value of w[i][1]
  //in other words, rs1 is the 32 lower bits of x[i] and rs2 is 32 higher bits

  val rs1             = io.decoupler_io.rocc_req_rs1
  val rs2             = io.decoupler_io.rocc_req_rs2
  val rs2_rs1         = Cat(rs2, rs1)

  val cmd_read        = (io.decoupler_io.rocc_req_cmd === ISA.READ) && valid
  val cmd_write       = (io.decoupler_io.rocc_req_cmd === ISA.WRITE) && valid

  val outputReg = RegInit(true.B)
  val validPrev = RegNext(valid, false.B) // Register to hold the previous value of valid



  //This part is dealing with memory
  //***************************************************************************************
  //***************************************************************************************
  //***************************************************************************************


  val rindex = RegInit(1.U(5.W))
  val busy = RegInit(false.B)

  //val m_idle :: m_read :: m_wait :: m_pad :: m_absorb :: Nil = Enum(UInt(), 5)
  //val mem_s = Reg(init=m_idle)

  val r_idle :: Nil = Enum(UInt(), 1)
  val rocc_s = Reg(init=r_idle)

  //hasher state
  val s_idle :: m_idle :: m_read :: s_write :: Nil = Enum(UInt(), 4)

  val state = Reg(init=s_idle)

  val in_addr = RegInit(0.U(32.W))
  val out_addr= RegInit(0.U(32.W))
  val data_len  = RegInit(0.U(32.W))
  val read  = RegInit(0.U(32.W))
  val mindex  = RegInit(0.U(5.W))
  val windex  = Reg(init = UInt(0,log2Up(32+1)))

  val dmem_resp_val_reg = RegNext(io.decoupler_io.dmem_resp_val)
  val dmem_resp_tag_reg = RegNext(io.decoupler_io.dmem_resp_tag)
  val writes_done  = Reg( init=Vec.fill(10) { Bool(false) })


  io.decoupler_io.busy := busy

  io.decoupler_io.sfence            := false.B
  io.decoupler_io.dmem_req_tag      := rindex
  io.decoupler_io.dmem_req_addr     := Bits(0, 32)
  io.decoupler_io.dmem_req_cmd      := M_XRD
  io.decoupler_io.dmem_req_size     := log2Ceil(8).U
  io.decoupler_io.dmem_req_val      := false.B

  io.decoupler_io.dmem_req_size:= log2Ceil(8).U

  switch(rocc_s) {
    is(r_idle) {
      //io.decoupler_io.rocc_req_ready := !busy
      when(io.decoupler_io.rocc_req_valid && !busy){
        when(cmd_write && funct == 6.U){
          //io.decoupler_io.rocc_req_ready := true.B
          in_addr  := rs1
          out_addr := rs2
          println("Input Addr: "+in_addr+", Output Addr: "+out_addr)
          io.decoupler_io.busy := true.B
        }.elsewhen(cmd_write && funct == 7.U) {
          busy := true.B
          //io.decoupler_io.rocc_req_ready := true.B
          io.decoupler_io.busy := true.B
          data_len := rs1
        }
      }
    }
  }


  switch(state) {
    is(m_idle){
      //we can start filling the buffer if we aren't writing and if we got a new message
      //or the hashing started
      //and there is more to read
      //and the buffer has been absorbed
      val canRead = busy &&  (read < data_len || (read === data_len && data_len === UInt(0)) )
      when(canRead){
        //buffer := Vec.fill(round_size_words){Bits(0,W)}
        //buffer_count := UInt(0)
        mindex := UInt(0)
        state := m_read
      }.otherwise{
        state := m_idle
      }
    }
    is(m_read) {
      //dmem signals
      //only read if we aren't writing
      when(state =/= s_write) {
        io.decoupler_io.dmem_req_val := read < data_len && mindex < 10.U
        io.decoupler_io.dmem_req_addr := in_addr
        io.decoupler_io.dmem_req_tag := mindex
        io.decoupler_io.dmem_req_cmd := M_XRD
        io.decoupler_io.dmem_req_size := log2Ceil(8).U

        when(io.decoupler_io.dmem_req_rdy && io.decoupler_io.dmem_req_val) {
          mindex := mindex + UInt(1)
          in_addr := in_addr + UInt(4)
          read := read + UInt(4) //read 8 bytes
          state := m_read
        }
      }
      //TODO: don't like special casing this
      when(data_len === UInt(0)) {
        read := UInt(1)
      }

    }

    is(s_write){
      //we are writing
      //request
      io.decoupler_io.dmem_req_val := windex < 10.U
      io.decoupler_io.dmem_req_addr := out_addr
      io.decoupler_io.dmem_req_tag := 0.B
      io.decoupler_io.dmem_req_cmd := M_XWR

      when(io.decoupler_io.dmem_req_rdy){
        windex := windex + UInt(1)
        out_addr := out_addr + UInt(8)
      }

      //response
      when(dmem_resp_val_reg){
        //there is a response from memory
        when(dmem_resp_tag_reg(4,0) >= 10) {
          //this is a response to a write
          writes_done(dmem_resp_tag_reg(4,0)-UInt(10)) := Bool(true)
        }
      }
      when(writes_done.reduce(_&&_)){
        //all the writes have been responded to
        //this is essentially reset time
        busy := Bool(false)

        writes_done := Vec.fill(10){Bool(false)}
        windex := UInt(10)
        rindex := UInt(10+1)
        in_addr := UInt(0)
        out_addr := UInt(0)
        data_len := UInt(0)
        read := UInt(0)
        state := s_idle
      }.otherwise{
        state := s_write
      }
    }
  }

  //Finish dealing with mem
  //***************************************************************************************
  //***************************************************************************************
  //***************************************************************************************



  //when(valid && !validPrev) { // Check for rising edge of valid
    outputReg := (!valid | validPrev) // Set output to 0 on rising edge of valid
  //}.otherwise {
  //  outputReg := true.B // Set output back to 1 otherwise
  //}

  io.decoupler_io.rocc_req_ready := outputReg

  io.bb_io.x0_in := x0_in_reg
  io.bb_io.x1_in := x1_in_reg
  io.bb_io.x2_in := x2_in_reg
  io.bb_io.x3_in := x3_in_reg
  io.bb_io.x4_in := x4_in_reg
  io.bb_io.rcon  := rcon_in_reg

  when((io.decoupler_io.rocc_req_cmd === ISA.WRITE) && doWrite_0 && valid) {
    x0_in_reg := rs2_rs1
  } .elsewhen((io.decoupler_io.rocc_req_cmd === ISA.WRITE) && doWrite_1 && valid){
    x1_in_reg := rs2_rs1
  } .elsewhen((io.decoupler_io.rocc_req_cmd === ISA.WRITE) && doWrite_2 && valid){
    x2_in_reg  := rs2_rs1
  } .elsewhen((io.decoupler_io.rocc_req_cmd === ISA.WRITE) && doWrite_3 && valid){
    x3_in_reg  := rs2_rs1
  } .elsewhen((io.decoupler_io.rocc_req_cmd === ISA.WRITE) && doWrite_4 && valid){
    x4_in_reg  := rs2_rs1
  } .elsewhen((io.decoupler_io.rocc_req_cmd === ISA.WRITE) && doWrite_rcon && valid){
    rcon_in_reg  := rs1(3, 0)
  }


  //req_rd := io.decoupler_io.rocc_req_rd
  io.decoupler_io.rocc_resp_rd  := io.decoupler_io.rocc_req_rd

  val cmdReadPrev = RegNext(cmd_read, false.B) // Register to hold the previous value of cmd_read

  //when(cmd_read && !cmdReadPrev) {
    io.decoupler_io.rocc_resp_valid := cmd_read && !cmdReadPrev // Set rocc_resp_valid on positive edge of cmd_read
  //}.otherwise {
  //  io.decoupler_io.rocc_resp_valid := false.B // Reset rocc_resp_valid otherwise
  //}


  when(cmd_read && funct === 0.U){
    io.decoupler_io.rocc_resp_data  := io.bb_io.x0_out(63, 32)
  } .elsewhen(cmd_read && funct === 1.U){
    io.decoupler_io.rocc_resp_data  := io.bb_io.x0_out(31, 0)
  } .elsewhen(cmd_read && funct === 2.U){
    io.decoupler_io.rocc_resp_data  := io.bb_io.x1_out(63, 32)
  } .elsewhen(cmd_read && funct === 3.U){
    io.decoupler_io.rocc_resp_data  := io.bb_io.x1_out(31, 0)
  } .elsewhen(cmd_read && funct === 4.U){
    io.decoupler_io.rocc_resp_data  := io.bb_io.x2_out(63, 32)
  } .elsewhen(cmd_read && funct === 5.U){
    io.decoupler_io.rocc_resp_data  := io.bb_io.x2_out(31, 0)
  } .elsewhen(cmd_read && funct === 6.U){
    io.decoupler_io.rocc_resp_data  := io.bb_io.x3_out(63, 32)
  } .elsewhen(cmd_read && funct === 7.U){
    io.decoupler_io.rocc_resp_data  := io.bb_io.x3_out(31, 0)
  } .elsewhen(cmd_read && funct === 8.U){
    io.decoupler_io.rocc_resp_data  := io.bb_io.x4_out(63, 32)
  } .elsewhen(cmd_read && funct === 9.U){
    io.decoupler_io.rocc_resp_data  := io.bb_io.x4_out(31, 0)
  }.otherwise{
    io.decoupler_io.rocc_resp_data := 0.U
  }


  }
