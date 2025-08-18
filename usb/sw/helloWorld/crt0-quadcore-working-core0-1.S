// See LICENSE.Sifive for license details.
#include <platform.h>
#include <smp.h>
#include "common.h"

  .section .data.init
  .align 2
allowed_hart:
  .word 0                // Initially, only hart 0 is allowed to run main

  .section .text.init
  .option norvc
  .globl _prog_start
_prog_start:
  // Get current hart id into a0
  csrr a0, mhartid       /* a0 = current hart id */
  
  // Load address of allowed_hart into t1
  la t1, allowed_hart
  
wait_loop:
  lw t2, 0(t1)         /* t2 = current allowed hart id */
  bne a0, t2, wait_loop /* loop until allowed_hart equals current hart id */

  // Now that this hart is allowed to run, initialize hardware
  csrw mie, s2         /* Set interrupt enables; contents of s2 assumed set elsewhere */
  li sp, (PAYLOAD_DEST + 0x1ff0)  /* Set up stack pointer; you might add a per-hart offset if desired */
  
  call main            /* Call the C main() function */

  // After main returns, update allowed_hart to (current hart id + 1)
  addi t2, a0, 1       /* Compute next allowed hart id */
  sw t2, 0(t1)         /* Store the new allowed hart id */

  // Optionally, wait (WFI) then loop indefinitely
  wfi
  j _loopback

_loopback:
  j _loopback         /* Infinite loop to keep the hart idle */
