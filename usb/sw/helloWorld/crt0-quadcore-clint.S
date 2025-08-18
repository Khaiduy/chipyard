// See LICENSE.Sifive for license details.
#include <platform.h>
#include <smp.h>
#include "common.h"

  .section .text.init
  .option norvc
  .globl _prog_start
_prog_start:
  li s2, 0x8  
  csrw mie, s2
  // perform boot if hart_0, otherwise sleep
  li s1, 0
  csrr s2, mhartid
  beq s1, s2, _execute_main
  wfi
  // wake up from first sleep, clear flag
  csrw mie, zero
  csrr s0, mhartid
_hart1_clear:
  li s1, 1
  bne s0, s1, _hart2_clear
  // if hart 1, clear flag
  li t0, (CLINT_CTRL_ADDR + CLINT_MSIP1)
  li t1, 0
  amoswap.w t1, t1, (t0)
  j _exit
_hart2_clear:
  li s1, 2
  bne s0, s1, _hart3_clear
  // if hart 2, clear flag
  li t0, (CLINT_CTRL_ADDR + CLINT_MSIP2)
  li t1, 0
  amoswap.w t1, t1, (t0)
  j _exit
_hart3_clear:
  li t0, (CLINT_CTRL_ADDR + CLINT_MSIP3)
  li t1, 0
  amoswap.w t1, t1, (t0)
  j _exit
_execute_main: // only perform by hart0
  li sp, (PAYLOAD_DEST + 0xFF0)
  csrr a0, mhartid
  call main
  // After booting, wake other hart from first sleep
  li t0, (CLINT_CTRL_ADDR + CLINT_MSIP1)
  li t1, 1
  amoswap.w t1, t1, (t0)
  li t0, (CLINT_CTRL_ADDR + CLINT_MSIP2)
  li t1, 1
  amoswap.w t1, t1, (t0)
  li t0, (CLINT_CTRL_ADDR + CLINT_MSIP3)
  li t1, 1
  amoswap.w t1, t1, (t0)
_exit:
  li s2, 0x8
  csrw mie, s2
  csrr a0, mhartid
  la a1, dtb // dtb address for next level bootloader
  li s1, MEMORY_MEM_ADDR
  jr s1
  wfi
_loopback:
  j _prog_start

  .section .dtb
  .align 3
dtb:
