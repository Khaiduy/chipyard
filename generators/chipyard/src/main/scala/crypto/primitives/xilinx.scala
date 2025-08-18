package chipyard.crypto.primitives

import chisel3._
import chisel3.util._
// import freechips.rocketchip.devices.tilelink._
// import freechips.rocketchip.diplomacy._
// import freechips.rocketchip.diplomaticobjectmodel.DiplomaticObjectModelAddressing
// import freechips.rocketchip.diplomaticobjectmodel.logicaltree._
// import freechips.rocketchip.diplomaticobjectmodel.model._
// import freechips.rocketchip.interrupts._
// import freechips.rocketchip.prci._
// import freechips.rocketchip.regmapper._
// import freechips.rocketchip.subsystem._
// import freechips.rocketchip.tilelink._

class xilinx_nand() extends Module {
  val io = IO(new Bundle{
    val i0 = Input(Bool())
    val i1 = Input(Bool())
    val out = Output(Bool())
  })
  val inst = Module(new xilinx_primitive_nand())
  inst.io.i0 := io.i0
  inst.io.i1 := io.i1
  io.out := inst.io.out
}

class xilinx_not() extends Module {
  val io = IO(new Bundle{
    val i0 = Input(Bool())
    val out = Output(Bool())
  })
  val inst = Module(new xilinx_primitive_not())
  inst.io.i0 := io.i0
  io.out := inst.io.out
}

class xilinx_fdre() extends Module {
  val io = IO(new Bundle(){
    val iClk = Input(Clock())
    val iRst = Input(Bool())
    val iD = Input(UInt(1.W))
    val oQ = Output(UInt(1.W))
  })

  val inst = Module(new xilinx_primitive_fdre())
  inst.io.i_clk := io.iClk
  inst.io.i_rst := io.iRst
  inst.io.i_d := io.iD
  io.oQ := inst.io.o_q
}

class xilinx_primitive_nand() extends BlackBox with HasBlackBoxInline{
  val io = IO(new Bundle(){
    //Inputs
    val i0 = Input(Bool())
    val i1 = Input(Bool())
    //Output
    val out = Output(Bool())
  })

  /*
  * NAND truth table
  * out - i0 i1
  * 1      0  0
  * 1      0  1
  * 1      1  0
  * 0      1  1
  * The config for INIT is 0x07
  * */

  setInline("xilinx_primitive_nand.v",
  s"""(* DONT_TOUCH = "yes" *) module xilinx_primitive_nand(
     |  input i0,
     |  input i1,
     |  output out
     |  );
     |  (* DONT_TOUCH = "yes" *) wire  w0;
     |  (* DONT_TOUCH = "yes" *) wire  w1;
     |  (* DONT_TOUCH = "yes" *) wire  w2;
     |  LUT6 #(
     |      .INIT(64'h0000000000000007)  // Specify LUT Contents
     |  ) LUT6_inst (
     |     .O(w2),   // LUT general output
     |     .I0(w0), // LUT input
     |     .I1(w1), // LUT input
     |     .I2(0), // LUT input
     |     .I3(0), // LUT input
     |     .I4(0), // LUT input
     |     .I5(0)  // LUT input
     |  );
     |
     |  assign w0 = i0;
     |  assign w1 = i1;
     |  assign out = w2;
     |  endmodule
     |""".stripMargin
  )
}

class xilinx_primitive_not() extends BlackBox with HasBlackBoxInline{
  val io = IO(new Bundle(){
    //Inputs
    val i0 = Input(Bool())
    //Output
    val out = Output(Bool())
  })

  /*
  * NAND truth table
  * out - i0
  * 1      0
  * 0      1
  * The config for INIT is 0x01
  * */

  setInline("xilinx_primitive_not.v",
    s"""(* DONT_TOUCH = "yes" *) module xilinx_primitive_not(
       |  input i0,
       |  output out
       |  );
       |
       |  (* DONT_TOUCH = "yes" *) wire  w0;
       |  (* DONT_TOUCH = "yes" *) wire  w1;
       |
       |  LUT6 #(
       |      .INIT(64'h0000000000000001)  // Specify LUT Contents
       |  ) LUT6_inst (
       |     .O(w1),   // LUT general output
       |     .I0(w0), // LUT input
       |     .I1(0), // LUT input
       |     .I2(0), // LUT input
       |     .I3(0), // LUT input
       |     .I4(0), // LUT input
       |     .I5(0)  // LUT input
       |  );
       |  assign w0 = i0;
       |  assign out = w1;
       |  endmodule
       |""".stripMargin
  )
}

class xilinx_primitive_fdre() extends BlackBox with HasBlackBoxInline {
  val io = IO(new Bundle(){
    val i_clk = Input(Clock())
    val i_rst = Input(Bool())
    val i_d = Input(UInt(1.W))
    val o_q = Output(UInt(1.W))
  })

  //     FDRE     : In order to incorporate this function into the design,
  //    Verilog   : the following instance declaration needs to be placed
  //   instance   : in the body of the design code.  The instance name
  //  declaration : (FDRE_inst) and/or the port declarations within the
  //     code     : parenthesis may be changed to properly reference and
  //              : connect this function to the design.  Delete or comment
  //              : out inputs/outs that are not necessary.

  //  <-----Cut code below this line---->

  // FDRE: Single Data Rate D Flip-Flop with Synchronous Reset and
  //       Clock Enable (posedge clk).
  //       Artix-7
  // Xilinx HDL Language Template, version 2022.1

  setInline("xilinx_primitive_fdre.v",
    s"""(* DONT_TOUCH = "yes" *) module xilinx_primitive_fdre(
       |  input i_clk,
       |  input i_rst,
       |  input i_d,
       |  output o_q
       |  );
       |
       |   (* DONT_TOUCH = "yes" *) wire  clk;
       |   (* DONT_TOUCH = "yes" *) wire  rst;
       |   (* DONT_TOUCH = "yes" *) wire  q;
       |   (* DONT_TOUCH = "yes" *) wire  d;
       |
       |   FDRE #(
       |      .INIT(1'b0) // Initial value of register (1'b0 or 1'b1)
       |   ) FDRE_inst (
       |      .Q(q),      // 1-bit Data output
       |      .C(clk),      // 1-bit Clock input
       |      .CE(1'b1),    // 1-bit Clock enable input
       |      .R(rst),      // 1-bit Synchronous reset input
       |      .D(d)       // 1-bit Data input
       |   );
       |
       |   assign clk = i_clk;
       |   assign rst = i_rst;
       |   assign d = i_d;
       |   assign o_q = q;
       |
       |  endmodule
       |""".stripMargin
  )
  // End of FDRE_inst instantiation
}
