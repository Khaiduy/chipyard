package chipyard.crypto.trng

// import chipsalliance.rocketchip.config.{Field, Parameters}
import chisel3._
import chisel3.util._
// import freechips.rocketchip.diplomacy._
// import freechips.rocketchip.diplomaticobjectmodel.model._
// import freechips.rocketchip.regmapper._
// import freechips.rocketchip.subsystem._
// import freechips.rocketchip.tilelink._
import freechips.rocketchip.util.ElaborationArtefacts


case class rgLocHints(
 loc_x: Int = 80,
 loc_y: Int = 299
)

class RingGenerator(val stage: Int = 32, val InjectNum: Int = 5, val injectList: List[Int], val feedbackSrc: List[Int], val feedbackDst: List[Int], val asic_impl: Boolean = false, val useXDC: Boolean = true, val hints: rgLocHints = rgLocHints()) extends Module {
  val io = IO(new Bundle {
    val i_rst = Input(Bool())
    val i_inject = Input(UInt(InjectNum.W))
    val i_en     = Input(Bool())
    val o_bit    = Output(UInt(1.W))
  })
  //default value
  val stateReg    = RegInit(VecInit(Seq.fill(stage)(0.U(1.W)))) // Creating a 32-bit register as a vector of 1-bit elements
  var injectNext   = 0;
  var feedbackNext = 0;

  // old code
  // stateReg := stateReg
  // when(io.i_en){
  //   stateReg(1) := stateReg(0)
  //   stateReg(0) := stateReg(stage-1)
  //   for (i <- 1 until (stage - 1)) {
  //     if ((injectNext < injectList.length) && (i == injectList(injectNext))) {
  //       stateReg(i + 1) := stateReg(i) ^ io.i_inject(injectNext)
  //       injectNext += 1
  //     } else if ((feedbackNext < feedbackDst.length) && (i == feedbackDst(feedbackNext))) {
  //       stateReg(i + 1) := stateReg(i) ^ stateReg(feedbackSrc(feedbackNext))
  //       feedbackNext += 1
  //     } else {
  //       stateReg(i + 1) := stateReg(i)
  //     }
  //   }
  // }.otherwise{
  //   for (i <- 0 until stage) {
  //     stateReg(i) := stateReg(i)
  //   }
  // }

  //new code
  
  when(io.i_rst){
    for (i <- 0 until stage) {
      stateReg(i) := 0.U
    }
  }.otherwise{
    stateReg(1) := stateReg(0)
    stateReg(0) := stateReg(stage-1)
    for (i <-1 until (stage -1)){
      if ((injectNext < injectList.length) && (i == injectList(injectNext))) {
        stateReg(i + 1) := stateReg(i) ^ io.i_inject(injectNext)
        injectNext += 1
      } else if ((feedbackNext < feedbackDst.length) && (i == feedbackDst(feedbackNext))) {
        stateReg(i + 1) := stateReg(i) ^ stateReg(feedbackSrc(feedbackNext))
        feedbackNext += 1
      } else {
        stateReg(i + 1) := stateReg(i)
      }
    }
  }

  io.o_bit := stateReg(stage-1)
//  when(io.i_en){
//    io.o_bit := stateReg(31)
//  }.otherwise(
//    io.o_bit := 0.U
//  )


  var FDRE_name = List("D5FF", "DFF","C5FF", "CFF","B5FF", "BFF","A5FF", "AFF")

  /* Create constraints based on location hint */
//  Test Ring Generator ref in ArtyA7Top.platform.trng_0.mod.rg <> platform/trng_0/mod/rg/
  if (useXDC) {
    ElaborationArtefacts.add(
      "ring_generator" + ".shell.xdc",
      {
        val xdcPath = pathName.split("\\.").drop(1).mkString("/")
        println(s"Test Ring Generator ref in ${pathName} <> ${xdcPath}")
        println(s"stateReg pathName: ${stateReg.pathName}")
        val variations =(for (i <- 0 until (stage/8)) yield {
            (for(j <- 0 until 8) yield{
              s"""set_property LOC SLICE_X${hints.loc_x}Y${hints.loc_y-i} [get_cells ${xdcPath}/stateReg_${i*8+j}_reg]
                 |set_property DONT_TOUCH true [get_cells ${xdcPath}/stateReg_${i*8+j}_reg]
                 |set_property BEL ${FDRE_name(j)} [get_cells ${xdcPath}/stateReg_${i*8+j}_reg]
                 |""".stripMargin
            }).reduce(_+_)
        }).reduce(_+_)

        val extra =
          s"""set_property ALLOW_COMBINATORIAL_LOOPS true [get_nets ${xdcPath}/stateReg_fdre_${stage-1}/inst/FDRE_inst/Q]
             |set_property SEVERITY {Warning} [get_drc_checks LUTLP-1]
             |set_property SEVERITY {Warning} [get_drc_checks NSTD-1]
             |""".stripMargin

        variations+extra
      }
    ) // ElaborationArtefacts
  }
}