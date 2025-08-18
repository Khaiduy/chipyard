package chipyard.crypto.trng

import chisel3._
import chisel3.util._
import freechips.rocketchip.util._
import chipyard.crypto.primitives._

case class roLocHints(
  loc_x: Int = 79,
  loc_y: Int = 299
)

class asic_not extends BlackBox with HasBlackBoxInline {
  val io = IO(new Bundle {
    val a = Input(Bool())
    val y = Output(Bool())
  })
  setInline("asic_not.v",
    """module asic_not(input wire a, output wire y);
      |  assign y = ~a;
      |endmodule
      |""".stripMargin)
}

class asic_nand extends BlackBox with HasBlackBoxInline {
  val io = IO(new Bundle {
    val a = Input(Bool())
    val b = Input(Bool())
    val y = Output(Bool())
  })
  setInline("asic_nand.v",
    """module asic_nand(input wire a, input wire b, output wire y);
      |  assign y = ~(a & b);
      |endmodule
      |""".stripMargin)
}


class RingOscillator(val stage: Int = 4 /*number of inverters*/,val asic_impl: Boolean = false, val useXDC: Boolean = true, val hints : roLocHints = roLocHints()) extends Module {
  val io = IO(new Bundle{
    val i_en  = Input(Bool())
    val o_out = Output(UInt((stage+1).W)) //output signal at each stage
  })

  val out = Wire(Vec(stage+1, Bool()))

  /* Generate elements depending on ASIC or FPGA*/
  
  val ro_invs = Wire(Vec(stage, Bool()))
  val ro_nand_out = Wire(Bool())

  if (!asic_impl) {
    // FPGA-specific instantiation
    val inv_modules = VecInit.tabulate(stage) { i =>
      val m = Module(new xilinx_not())
      m.suggestName(s"not_gate_${i}")
      m.io
    }
    val nand_module = Module(new xilinx_nand())
    nand_module.suggestName("nand_gate_0")

    // Connect the NAND gate
    nand_module.io.i1 := WireDefault(false.B) // placeholder, will connect later
    nand_module.io.i0 := io.i_en.asUInt

    // Connect inverter inputs
    for (i <- 0 until stage) {
      inv_modules(i).i0 := WireDefault(false.B) // placeholder, will connect later
      ro_invs(i) := inv_modules(i).out
    }

    // Save NAND output
    ro_nand_out := nand_module.io.out

    // Feedback wiring
    nand_module.io.i1 := ro_invs(stage - 1)
    inv_modules(0).i0 := ro_nand_out
    for (i <- 1 until stage) {
      inv_modules(i).i0 := ro_invs(i - 1)
    }

  } else {
    // --- ASIC implementation using BlackBox NOT/NAND ---
    val inv_modules = VecInit.tabulate(stage) { i =>
      val m = Module(new asic_not())
      m.suggestName(s"asic_not_${i}")
      m.io
    }

    val nand_module = Module(new asic_nand())
    nand_module.suggestName("asic_nand_0")

    // Feedback wiring
    nand_module.io.b := inv_modules(stage - 1).y
    nand_module.io.a := io.i_en
    inv_modules(0).a := nand_module.io.y
    for (i <- 1 until stage) {
      inv_modules(i).a := inv_modules(i - 1).y
    }

    for (i <- 0 until stage) {
      ro_invs(i) := inv_modules(i).y
    }

    ro_nand_out := nand_module.io.y
  }

  out(0) := ro_nand_out
  for (i <- 0 until stage) {
    out(i+1) := ro_invs(i)
  }
  io.o_out := out.asUInt



  // val ro_invs = VecInit.tabulate(stage) { i =>
  //   val m = Module(new xilinx_not())
  //   m.suggestName(s"not_gate_${i}")
  //   m.io
  // }

  // val ro_nand = VecInit.tabulate(1){ i =>
  //   val m = Module(new xilinx_nand())
  //   m.suggestName((s"nand_gate_${i}"))
  //   m.io
  // }

  // /* Structure of the ring osc */
  // for(i <- 0 until (stage-1)){
  //   if(i==0){
  //     ro_nand(i).i1 := ro_invs(stage-1).out
  //     ro_nand(i).i0 := io.i_en.asUInt
  //     ro_invs(i).i0 := ro_nand(i).out
  //   }
  //   ro_invs(i+1).i0 := ro_invs(i).out
  // }


  /* Output Logic */

  // out(0) := ro_nand(0).out
  // for(i <- 0 until stage){
  //   out(i+1) := ro_invs(i).out
  // }
  // io.o_out := out.asUInt

  /* Create constraints based on location hint */
  if (useXDC) {
    ElaborationArtefacts.add(
      "ring_oscillator" + ".shell.xdc",
      {
        val xdcPath = pathName.split("\\.").drop(1).mkString("/") + "/"
        println(s"Test Ring Oscillator ref in ${pathName} <> ${xdcPath}")
        val nand_xdc =
          s"""set_property LOC SLICE_X${hints.loc_x}Y${hints.loc_y} [get_cells ${xdcPath}ro_nand_nand_gate_0/inst/LUT6_inst]
             |set_property DONT_TOUCH TRUE [get_cells ${xdcPath}ro_nand_nand_gate_0/inst/LUT6_inst]
             |set_property BEL D6LUT [get_cells ${xdcPath}ro_nand_nand_gate_0/inst/LUT6_inst]
             |set_property ALLOW_COMBINATORIAL_LOOPS TRUE [get_nets ${xdcPath}ro_nand_nand_gate_0/inst/w2]
             |""".stripMargin

        val not_xdc = (for(i <- 0 until stage) yield {
          s"""
             |set_property LOC SLICE_X${hints.loc_x}Y${hints.loc_y - i - 1} [get_cells ${xdcPath}ro_invs_not_gate_${i}/inst/LUT6_inst]
             |set_property DONT_TOUCH TRUE [get_cells ${xdcPath}ro_invs_not_gate_${i}/inst/LUT6_inst]
             |set_property BEL D6LUT [get_cells ${xdcPath}ro_invs_not_gate_${i}/inst/LUT6_inst]
             |set_property ALLOW_COMBINATORIAL_LOOPS TRUE [get_nets ${xdcPath}ro_invs_not_gate_${i}/inst/w1]
             |""".stripMargin
        }).reduce(_+_)

        val extra =
          s"""create_clock -name clk_ro -period 10 [get_pins ${xdcPath}ro_invs_not_gate_${stage-1}/inst/LUT6_inst/O]
             |set_property SEVERITY {Warning} [get_drc_checks LUTLP-1]
             |""".stripMargin

        nand_xdc + not_xdc + extra
      }
    ) // ElaborationArtefacts
  }
}