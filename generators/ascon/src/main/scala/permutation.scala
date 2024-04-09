package ascon

import chisel3._
import chisel3.util._

class ASCONSbox() extends Module{
  val io = IO(new Bundle{
    val in = Input(Vec(5,UInt(64.W)))
    val r = Input(UInt(4.W))
    val out = Output(Vec(5,UInt(64.W)))
  })
  val crtable = Wire(Vec(12,UInt(8.W)))
  for(i <- 0 until 12) yield{
    crtable(i) := (0xf0 - i*0x10 + i*0x1).U
  }

  // --- substitution layer ---
  val xorwire = Wire(Vec(5,UInt(64.W)))
  val constant = Wire(UInt(8.W))
  //val t2 = Wire(UInt(4.W))

  //t2 := (0xC.U(4.W) - io.r)
  constant := ((0x3.U(4.W) + io.r) << 4) | (0xC.U(4.W) - io.r)


  xorwire := io.in
  xorwire(0) := io.in(0) ^ io.in(4)
  xorwire(2) := io.in(2) ^ io.in(1) ^ constant
  xorwire(4) := io.in(4) ^ io.in(3)

  val txorwire = Wire(Vec(5,UInt(64.W)))
  for(i <- 0 until 5){
    // val t = (xorwire((i+1)%5) ^ (0xFFFFFFFFFFFFFFFF).U) & xorwire((i+2)%5)
    val t = ~xorwire((i+1)%5) & xorwire((i+2)%5)
    txorwire(i) := xorwire(i) ^ t
  }
  io.out(0) := txorwire(0) ^ txorwire(4)
  io.out(1) := txorwire(1) ^ txorwire(0)
  io.out(2) := ~txorwire(2)
  io.out(3) := txorwire(3) ^ txorwire(2)
  io.out(4) := txorwire(4)
  // io.out(2) := io.out(2) ^ BigInt(0XFFFFFFFFFFFFFFFF,16).U
}

class ASCONLinear() extends Module{
  val io = IO(new Bundle{
    val in = Input(Vec(5,UInt(64.W)))
    val out = Output(Vec(5,UInt(64.W)))
  })
  io.out(0) := io.in(0) ^ io.in(0).rotateRight(19) ^ io.in(0).rotateRight(28)
  io.out(1) := io.in(1) ^ io.in(1).rotateRight(61) ^ io.in(1).rotateRight(39)
  io.out(2) := io.in(2) ^ io.in(2).rotateRight(1) ^ io.in(2).rotateRight(6)
  io.out(3) := io.in(3) ^ io.in(3).rotateRight(10) ^ io.in(3).rotateRight(17)
  io.out(4) := io.in(4) ^ io.in(4).rotateRight(7) ^ io.in(4).rotateRight(41)
}

class ASCONPermuitation() extends Module {
  val io = IO(new Bundle{
    val in = Input(Vec(5,UInt(64.W)))
    val r = Input(UInt(4.W))
    val out = Output(Vec(5,UInt(64.W)))
  })

  val sbox = Module(new ASCONSbox)
  val linear = Module(new ASCONLinear)
  sbox.io.in := io.in
  sbox.io.r := io.r
  // --- add round constants ---
  //sbox.io.in(2) := io.in(2) ^ crtable(io.r)
  linear.io.in := sbox.io.out
  io.out := linear.io.out
}

