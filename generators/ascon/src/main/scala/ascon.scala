package ascon

import Chisel.{Bits, Bool, DecoupledIO, Module, RegEnable, Wire}
import chisel3._
import chisel3.util.HasBlackBoxResource
import freechips.rocketchip.tile._
import org.chipsalliance.cde.config._
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.rocket.constants.MemoryOpConstants
import freechips.rocketchip.rocket.{HellaCacheReq, TLBConfig}

//case object myroccXLen extends Field[Int]
case object AsconBlackBox extends Field[Boolean](false)
class myPermutation_bb_IO (xLen: Int = 32)(implicit p: Parameters) extends Bundle {
  val rcon  = Input(UInt(4.W))
  val x0_out    = Output(UInt(64.W))
  val x1_out    = Output(UInt(64.W))
  val x2_out    = Output(UInt(64.W))
  val x3_out    = Output(UInt(64.W))
  val x4_out    = Output(UInt(64.W))
  val x0_in    = Input(UInt(64.W))
  val x1_in    = Input(UInt(64.W))
  val x2_in    = Input(UInt(64.W))
  val x3_in    = Input(UInt(64.W))
  val x4_in    = Input(UInt(64.W))
}

class asconp (xLen: Int = 32)(implicit p: Parameters) extends BlackBox with HasBlackBoxResource {
  val io = IO(new myPermutation_bb_IO(xLen))

  addResource("/vsrc/asconp.v")
}

class MyAsconAccel (opcodes: OpcodeSet)(implicit p: Parameters) extends LazyRoCC (
  opcodes   = opcodes, nPTWPorts = if (p(AsconTLB).isDefined) 1 else 0) {
  override lazy val module = new MyAsconAccelImp(this)
  val dmemOpt = p(AsconTLB).map { _ =>
    val dmem = LazyModule(new DmemModule)
    tlNode := dmem.node
    dmem
  }
}

class MyAsconAccelImp(outer: MyAsconAccel)(implicit p: Parameters) extends LazyRoCCModuleImp(outer)
  with HasL1CacheParameters
  with HasCoreParameters {

  chisel3.dontTouch(io)

  override val xLen = 32

  val cacheParams = tileParams.dcache.get

  // Instantiate the rocc modules
  val myroccDecoupler  = Module(new RoCCDecoupler(1, xLen))

  val myroccController = Module(new RoCCController(xLen))

  // Connect
  io <> myroccDecoupler.io.rocc_io
  myroccDecoupler.io.clock := clock
  myroccDecoupler.io.reset := reset.asUInt

  myroccController.io.decoupler_io <> myroccDecoupler.io.controller_io
  myroccController.io.clock := clock
  myroccController.io.reset := reset.asUInt

  val status = RegEnable(io.cmd.bits.status, io.cmd.fire())


  //val dmem_data = Wire(UInt(coreDataBits.W))
  def dmem_ctrl(req: DecoupledIO[HellaCacheReq]) {
    req.valid := myroccController.io.decoupler_io.dmem_req_val
    myroccController.io.decoupler_io.dmem_req_rdy := req.ready
    req.bits.tag := myroccController.io.decoupler_io.dmem_req_tag
    req.bits.addr := myroccController.io.decoupler_io.dmem_req_addr
    req.bits.cmd := myroccController.io.decoupler_io.dmem_req_cmd
    req.bits.size := myroccController.io.decoupler_io.dmem_req_size
    req.bits.data := myroccController.io.decoupler_io.dmem_req_data
    req.bits.signed := Bool(false)
    req.bits.dprv := status.dprv
    req.bits.dv := status.dv
    req.bits.phys := Bool(false)
  }

  outer.dmemOpt match {
    case Some(m) => {
      val dmem = m.module
      //dmem_ctrl(dmem.io.req)
      dmem.io.req.valid := myroccController.io.decoupler_io.dmem_req_val
      myroccController.io.decoupler_io.dmem_req_rdy := dmem.io.req.ready
      dmem.io.req.bits.tag := myroccController.io.decoupler_io.dmem_req_tag
      dmem.io.req.bits.addr := myroccController.io.decoupler_io.dmem_req_addr
      dmem.io.req.bits.cmd := myroccController.io.decoupler_io.dmem_req_cmd
      dmem.io.req.bits.size := myroccController.io.decoupler_io.dmem_req_size
      dmem.io.req.bits.data := myroccController.io.decoupler_io.dmem_req_data
      dmem.io.req.bits.signed := Bool(false)
      dmem.io.req.bits.dprv := status.dprv
      dmem.io.req.bits.dv := status.dv
      dmem.io.req.bits.phys := Bool(false)

      dmem.io.mem <> myroccDecoupler.io.mem_cache
      myroccDecoupler.io.ptw <> dmem.io.ptw
      //println("Mem was declared")
      dmem.io.status := status
      dmem.io.sfence := myroccController.io.decoupler_io.sfence
    }
    case None => dmem_ctrl(myroccDecoupler.io.rocc_io.mem.req)
  }

  //dmem_data := myroccController.io.decoupler_io.buffer_out

  if (p(AsconBlackBox)) {
    val myroccBlackBox   = Module(new asconp(xLen))
    myroccController.io.bb_io <> myroccBlackBox.io
  } else {
    val myAsconPermutation   = Module(new ASCONPermuitation)
    myroccController.io.bb_io.x0_out := myAsconPermutation.io.out(0)
    myroccController.io.bb_io.x1_out := myAsconPermutation.io.out(1)
    myroccController.io.bb_io.x2_out := myAsconPermutation.io.out(2)
    myroccController.io.bb_io.x3_out := myAsconPermutation.io.out(3)
    myroccController.io.bb_io.x4_out := myAsconPermutation.io.out(4)
    myAsconPermutation.io.in(0) := myroccController.io.bb_io.x0_in
    myAsconPermutation.io.in(1) := myroccController.io.bb_io.x1_in
    myAsconPermutation.io.in(2) := myroccController.io.bb_io.x2_in
    myAsconPermutation.io.in(3) := myroccController.io.bb_io.x3_in
    myAsconPermutation.io.in(4) := myroccController.io.bb_io.x4_in
    myAsconPermutation.io.r := myroccController.io.bb_io.rcon

  }


}