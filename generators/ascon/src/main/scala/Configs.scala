package ascon

import chisel3._
import chisel3.util.{HasBlackBoxResource}
import freechips.rocketchip.tile._
import org.chipsalliance.cde.config._
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.rocket.{TLBConfig, HellaCacheReq}

class WithAsconRoccAccel extends Config ((site, here, up) => {
  case AsconBlackBox => false
  case BuildRoCC => up(BuildRoCC) ++ Seq(
    (p: Parameters) => {
      val asconRocc = LazyModule.apply(new MyAsconAccel(OpcodeSet.custom1 | OpcodeSet.custom0)(p))
      asconRocc
    }
  )
})

class WithAsconRoccAccelBlackbox extends Config ((site, here, up) => {
  case AsconBlackBox => true
  case BuildRoCC => up(BuildRoCC) ++ Seq(
    (p: Parameters) => {
      val asconRocc = LazyModule.apply(new MyAsconAccel(OpcodeSet.custom1 | OpcodeSet.custom0)(p))
      asconRocc
    }
  )
})

class WithAccumExample extends Config ((site, here, up) => {

  case BuildRoCC => up(BuildRoCC) ++ Seq(
    (p: Parameters) => {
      val accumulator = LazyModule(new CharCountExample(OpcodeSet.custom2)(p))
      accumulator
    }
  )
})

class WithAsconRoccAccelCache extends Config ((site, here, up) => {
  case AsconBlackBox => false
  case AsconTLB => Some(TLBConfig(nSets = 1, nWays = 4, nSectors = 1, nSuperpageEntries = 1))
  case BuildRoCC => up(BuildRoCC) ++ Seq(
    (p: Parameters) => {
      val asconRocc = LazyModule.apply(new MyAsconAccel(OpcodeSet.custom1 | OpcodeSet.custom0)(p))
      asconRocc
      }
  )
})