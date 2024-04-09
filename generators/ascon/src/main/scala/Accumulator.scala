package ascon

import chisel3._
import chisel3.util._
import chisel3.util.HasBlackBoxResource
import org.chipsalliance.cde.config._
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.rocket._
import freechips.rocketchip.tilelink._
import freechips.rocketchip.util._
import freechips.rocketchip.tile._


class  CharCountExample(opcodes: OpcodeSet)(implicit p: Parameters) extends LazyRoCC(opcodes) {
  override lazy val module = new CharCountExampleModuleImp(this)
  override val atlNode = TLClientNode(Seq(TLMasterPortParameters.v1(Seq(TLMasterParameters.v1("CharacterCountRoCC")))))
}

class CharCountExampleModuleImp(outer: CharCountExample)(implicit p: Parameters) extends LazyRoCCModuleImp(outer)
  with HasCoreParameters
  with HasL1CacheParameters {
  val cacheParams = tileParams.dcache.get

  private val blockOffset = blockOffBits
  private val beatOffset = log2Up(cacheDataBits/8)

  val needle = Reg(UInt(8.W))
  val addr = Reg(UInt(coreMaxAddrBits.W))
  val count = Reg(UInt(xLen.W))
  val resp_rd = Reg(chiselTypeOf(io.resp.bits.rd))

  val addr_block = addr(coreMaxAddrBits - 1, blockOffset)
  val offset = addr(blockOffset - 1, 0)
  val next_addr = (addr_block + 1.U) << blockOffset.U

  val s_idle :: s_acq :: s_gnt :: s_check :: s_resp :: Nil = Enum(5)
  val state = RegInit(s_idle)

  val (tl_out, edgesOut) = outer.atlNode.out(0)
  val gnt = tl_out.d.bits
  val recv_data = Reg(UInt(cacheDataBits.W))
  val recv_beat = RegInit(0.U(log2Up(cacheDataBeats+1).W))

  val data_bytes = VecInit(Seq.tabulate(cacheDataBits/8) { i => recv_data(8 * (i + 1) - 1, 8 * i) })
  val zero_match = data_bytes.map(_ === 0.U)
  val needle_match = data_bytes.map(_ === needle)
  val first_zero = PriorityEncoder(zero_match)

  val chars_found = PopCount(needle_match.zipWithIndex.map {
    case (matches, i) =>
      val idx = Cat(recv_beat - 1.U, i.U(beatOffset.W))
      matches && idx >= offset && i.U <= first_zero
  })
  val zero_found = zero_match.reduce(_ || _)
  val finished = Reg(Bool())

  io.cmd.ready := (state === s_idle)
  io.resp.valid := (state === s_resp)
  io.resp.bits.rd := resp_rd
  io.resp.bits.data := count
  tl_out.a.valid := (state === s_acq)
  tl_out.a.bits := edgesOut.Get(
    fromSource = 0.U,
    toAddress = addr_block << blockOffset,
    lgSize = lgCacheBlockBytes.U)._2
  tl_out.d.ready := (state === s_gnt)

  when (io.cmd.fire()) {
    addr := io.cmd.bits.rs1
    needle := io.cmd.bits.rs2
    resp_rd := io.cmd.bits.inst.rd
    count := 0.U
    finished := false.B
    state := s_acq
  }

  when (tl_out.a.fire()) { state := s_gnt }

  when (tl_out.d.fire()) {
    recv_beat := recv_beat + 1.U
    recv_data := gnt.data
    state := s_check
  }

  when (state === s_check) {
    when (!finished) {
      count := count + chars_found
    }
    when (zero_found) { finished := true.B }
    when (recv_beat === cacheDataBeats.U) {
      addr := next_addr
      state := Mux(zero_found || finished, s_resp, s_acq)
      recv_beat := 0.U
    } .otherwise {
      state := s_gnt
    }
  }

  when (io.resp.fire()) { state := s_idle }

  io.busy := (state =/= s_idle)
  io.interrupt := false.B
  io.mem.req.valid := false.B
  // Tie off unused channels
  tl_out.b.ready := true.B
  tl_out.c.valid := false.B
  tl_out.e.valid := false.B
}