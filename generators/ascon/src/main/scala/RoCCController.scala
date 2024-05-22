//see LICENSE for license
//authors: Duy
package ascon

import chisel3._

import Chisel.{Bits, Bool, Cat, Reg, UInt, Vec, is, log2Ceil, log2Up, switch, when}
import freechips.rocketchip.tile.{HasCoreParameters}
import freechips.rocketchip.rocket.constants.MemoryOpConstants
import org.chipsalliance.cde.config._


object State extends ChiselEnum {
  val s_idle, s_read, s_write, s_wait, s_wait_2, r_idle = Value
}

import State._

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
  val dmem_req_data     = Output(UInt(xLen.W))

  val dmem_resp_val     = Input(Bool())
  val dmem_resp_tag     = Input(UInt(7.W))
  val dmem_resp_data    = Input(UInt(xLen.W))

  val sfence            = Output(Bool())

  val buffer_out    = Output(UInt(xLen.W))
}

class RoCCControllerIO (xLen: Int = 32)(implicit p: Parameters) extends Bundle {
  // Control signals
  val clock = Input(Clock())
  val reset = Input(UInt(1.W))

  // Controller-Decoupler interface
  val decoupler_io = new ControllerDecouplerIO(xLen)

  // Black box interface
  val bb_io = Flipped(new myPermutation_bb_IO(xLen))
}

class RoCCController (override val xLen: Int)(override implicit val p: Parameters) extends Module
  with HasCoreParameters
  with MemoryOpConstants {

  val io = IO(new RoCCControllerIO(xLen)(p))
  //val req_rd          = Reg(chiselTypeOf(io.decoupler_io.rocc_resp_rd))

  val funct           = io.decoupler_io.rocc_req_funct
  //val doWrite_0       = funct === 0.U
  //val doWrite_1       = funct === 1.U
  //val doWrite_2       = funct === 2.U
  //val doWrite_3       = funct === 3.U
  //val doWrite_4       = funct === 4.U
  //val doWrite_rcon    = funct === 5.U

  val valid           = io.decoupler_io.rocc_req_valid
  //val x0_in_reg       = Reg(UInt(64.W))
  //val x1_in_reg       = Reg(UInt(64.W))
  //val x2_in_reg       = Reg(UInt(64.W))
  //val x3_in_reg       = Reg(UInt(64.W))
  //val x4_in_reg       = Reg(UInt(64.W))
  val rcon_in_reg     = Reg(UInt(4.W))

  //NOTE: For ascon_state_t union
  //As rs1 and rs2 is 32 bits,
  //rs1 is the value of w[i][0] and rs2 is the value of w[i][1]
  //in other words, rs1 is the 32 lower bits of x[i] and rs2 is 32 higher bits

  val rs1             = io.decoupler_io.rocc_req_rs1
  val rs2             = io.decoupler_io.rocc_req_rs2
  //val rs2_rs1         = Cat(rs2, rs1)

  val cmd_read        = (io.decoupler_io.rocc_req_cmd === ISA.READ) && valid
  val cmd_write       = (io.decoupler_io.rocc_req_cmd === ISA.WRITE) && valid

  //val outputReg = RegInit(true.B)
  //val validPrev = RegNext(valid, false.B) // Register to hold the previous value of valid



  //This part is dealing with memory
  //***************************************************************************************
  //***************************************************************************************
  //***************************************************************************************

  val buffer = Reg(init=Vec.fill(10) { 0.U(32.W) })
  val buffer_count = Reg(init = UInt(0,5))
  val buffer_valid = RegInit(false.B)
  val rindex = RegInit(1.U(5.W))
  val busy = RegInit(false.B)

  val stateReg = RegInit(s_idle)
  val rocc_s = RegInit(r_idle)


  val in_addr = RegInit(0.U(32.W))
  val out_addr= RegInit(0.U(32.W))
  val data_len  = RegInit(0.U(32.W))

  val read  = RegInit(0.U(32.W))
  val mindex  = RegInit(0.U(5.W))
  val windex  = Reg(init = UInt(0,log2Up(32+1)))

  val dmem_resp_val_reg = RegNext(io.decoupler_io.dmem_resp_val)
  val dmem_resp_tag_reg = RegNext(io.decoupler_io.dmem_resp_tag)
  val writes_done  = Reg( init=Vec.fill(10) { Bool(false) })

  io.decoupler_io.buffer_out := buffer(mindex)
  io.decoupler_io.busy := busy

  io.decoupler_io.sfence            := false.B
  io.decoupler_io.dmem_req_tag      := rindex
  io.decoupler_io.dmem_req_addr     := Bits(0, 32)
  io.decoupler_io.dmem_req_cmd      := M_XRD
  io.decoupler_io.dmem_req_size     := log2Ceil(4).U
  io.decoupler_io.dmem_req_val      := false.B
  io.decoupler_io.dmem_req_data     := Bits(0, 32)

  io.decoupler_io.rocc_req_ready    := false.B

  val bbOutVec = VecInit(Seq(
    io.bb_io.x0_out(31, 0),
    io.bb_io.x0_out(63, 32),
    io.bb_io.x1_out(31, 0),
    io.bb_io.x1_out(63, 32),
    io.bb_io.x2_out(31, 0),
    io.bb_io.x2_out(63, 32),
    io.bb_io.x3_out(31, 0),
    io.bb_io.x3_out(63, 32),
    io.bb_io.x4_out(31, 0),
    io.bb_io.x4_out(63, 32)
  ))
  switch(rocc_s) {
    is(r_idle) {
      io.decoupler_io.rocc_req_ready := !busy
      when(valid && !busy) {
        when(cmd_write && funct === 6.U) {
          io.decoupler_io.rocc_req_ready := true.B
          in_addr := rs1
          out_addr := rs1
          data_len := 0x28.U
          rcon_in_reg := rs2
          io.decoupler_io.rocc_req_ready := true.B
          busy := true.B
          //println("Input Addr: "+in_addr+", Output Addr: "+out_addr)
          io.decoupler_io.busy := true.B
        }/*.elsewhen(cmd_write && funct === 7.U) {
          busy := true.B
          io.decoupler_io.rocc_req_ready := true.B
          io.decoupler_io.busy := true.B
          data_len := 0x28.U
          rcon_in_reg := rs1
        }*/
      }
    }
  }


  switch(stateReg) {
    is(s_idle){
      //we can start filling the buffer if we aren't writing and if we got a new message
      //or the hashing started
      //and there is more to read
      //and the buffer has been absorbed
      val canRead = busy && (read < data_len || (read === data_len && data_len === UInt(0)) && buffer_count === UInt(0))
      when(canRead){
        mindex := UInt(0)
        stateReg := s_read
      }.otherwise{
        stateReg := s_idle
      }
    }
    is(s_read) {
      //dmem signals
      //only read if we aren't writing
      //when(stateReg =/= s_write) {
        io.decoupler_io.dmem_req_val := read < data_len && mindex < 10.U
        io.decoupler_io.dmem_req_addr := in_addr
        io.decoupler_io.dmem_req_tag := mindex
        io.decoupler_io.dmem_req_cmd := M_XRD
        io.decoupler_io.dmem_req_size := log2Ceil(4).U

        when(io.decoupler_io.dmem_req_rdy && io.decoupler_io.dmem_req_val) {
          mindex := mindex + UInt(1)
          in_addr := in_addr + UInt(4)
          read := read + UInt(4) //read 4 bytes
          //stateReg := s_wait
        }
      //}
      //TODO: don't like special casing this
      when(data_len === UInt(0)) {
        read := UInt(1)
      }

      //next state
      when(mindex < UInt(10 -1)){
        //TODO: in pad check buffer_count ( or move on to next thread?)
        when(data_len > read){
          //not sure if this case will be used but this means we haven't
          //sent all the requests yet (maybe back pressure causes this)
          stateReg := s_read
        }.otherwise{
          //its ok we didn't send them all because the message wasn't big enough
          buffer_valid := Bool(false)
          //mem_s := m_pad
          //pindex := words_filled
        }
      }.otherwise{
        when(mindex < UInt(10) && !(io.decoupler_io.dmem_req_rdy && io.decoupler_io.dmem_req_val)){
          //we are still waiting to send the last request
          stateReg := s_read
        }.otherwise{
          //we have reached the end of this chunk
          mindex := mindex + UInt(1)
          in_addr := in_addr + UInt(4)
          read := read + UInt(4)//read 8 bytes
          //we sent all the requests
          when((data_len < (read+UInt(4) ))){
            //but the buffer still isn't full
            //buffer_valid := Bool(false)
            //mem_s := m_pad
            //pindex := words_filled
          }.otherwise{
            //we have more to read eventually
            stateReg := s_wait
          }
        }
      }
    }
    is(s_wait){
      stateReg := s_wait_2
    }
    is(s_wait_2){
      stateReg := s_write
    }
    is(s_write){
      //we are writing
      //request

      io.decoupler_io.dmem_req_val := windex < 10.U
      io.decoupler_io.dmem_req_addr := out_addr
      io.decoupler_io.dmem_req_tag := 10.U + windex
      io.decoupler_io.dmem_req_cmd := M_XWR
      io.decoupler_io.dmem_req_data := bbOutVec(windex)

      when(io.decoupler_io.dmem_req_rdy && io.decoupler_io.dmem_req_val){
        windex := windex + UInt(1)
        out_addr := out_addr + UInt(4)
        io.decoupler_io.dmem_req_data := bbOutVec(windex)
      }

      //response
      when(dmem_resp_val_reg){
        //there is a response from memory
        when(dmem_resp_tag_reg(4,0) >= 10.U) {
          //this is a response to a write
          writes_done(dmem_resp_tag_reg(4,0)-10.U) := Bool(true)
        }
      }

      when(writes_done.reduce(_&&_)){
        //all the writes have been responded to
        //this is essentially reset time
        busy := false.B

        writes_done := Vec.fill(10){Bool(false)}
        windex := UInt(0)
        rindex := UInt(0)
        buffer_count := UInt(0)
        in_addr := UInt(0)
        out_addr := UInt(0)
        data_len := UInt(0)
        //hashed := UInt(0)
        read := UInt(0)
        buffer_valid := Bool(false)
        //io.init := Bool(true)
        stateReg := s_idle
      }.otherwise{
        stateReg := s_write
      }
    }
  }

  when(io.decoupler_io.dmem_resp_val) {
    when(io.decoupler_io.dmem_resp_tag(4,0) < 10.U){
      //This is read response
      buffer(io.decoupler_io.dmem_resp_tag(4,0)) := io.decoupler_io.dmem_resp_data
      buffer_count := buffer_count + UInt(1)
    }.otherwise{
      //busy := false.B
    }
  }
  when(buffer_count >= (mindex) && (mindex >= UInt(10))){// ||
    //read(i) > msg_len(i))){
    when(read > data_len){
      //padding needed
    }.otherwise{
      //next cycle the buffer will be valid
      //buffer_valid := Bool(true)
    }
  }
  io.bb_io.x0_in := Cat(buffer(1), buffer(0))
  io.bb_io.x1_in := Cat(buffer(3), buffer(2))
  io.bb_io.x2_in := Cat(buffer(5), buffer(4))
  io.bb_io.x3_in := Cat(buffer(7), buffer(6))
  io.bb_io.x4_in := Cat(buffer(9), buffer(8))

  //Finish dealing with mem
  //***************************************************************************************
  //***************************************************************************************
  //***************************************************************************************



  //when(valid && !validPrev) { // Check for rising edge of valid
    //outputReg := (!valid | validPrev) // Set output to 0 on rising edge of valid
  //}.otherwise {
  //  outputReg := true.B // Set output back to 1 otherwise
  //}

  //io.decoupler_io.rocc_req_ready := outputReg

  //io.bb_io.x0_in := x0_in_reg
  //io.bb_io.x1_in := x1_in_reg
  //io.bb_io.x2_in := x2_in_reg
  //io.bb_io.x3_in := x3_in_reg
  //io.bb_io.x4_in := x4_in_reg
  io.bb_io.rcon  := rcon_in_reg
  val cmdReadPrev = RegNext(cmd_read, false.B) // Register to hold the previous value of cmd_read
  io.decoupler_io.rocc_resp_valid := cmd_read && !cmdReadPrev // Set rocc_resp_valid on positive edge of cmd_read
  io.decoupler_io.rocc_resp_rd  := io.decoupler_io.rocc_req_rd
  io.decoupler_io.rocc_resp_data := Bits(0, 32)
/*
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

*/
  }
