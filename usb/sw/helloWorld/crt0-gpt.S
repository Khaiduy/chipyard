#define MAIN_PROGRAM_ADDR 0x80000000
#define BOOT_TOKEN_ADDR   0x80001000  // shared memory location for boot token

.section .text.start, "ax", @progbits
.globl _start
_start:
  csrr a0, mhartid            // Get current hart ID

  // --- Wait until BOOT_TOKEN == mhartid ---
boot_wait_loop:
  li t1, BOOT_TOKEN_ADDR      // Address of boot token
  lw t2, 0(t1)                // Read token
  bne t2, a0, boot_wait_loop  // Wait until token == hart ID

  // --- Increment token for the next hart ---
  addi t2, a0, 1              // t2 = next hart ID
  sw t2, 0(t1)                // store next hart ID to allow next hart to boot

  // --- Jump to main program at 0x80000000 ---
  li a0, MAIN_PROGRAM_ADDR    // Hardcoded address of main
  csrw mepc, a0               // Set return PC to main
  li a1, 0x80
  csrc mstatus, a1            // Clear MPIE before mret
  mret

.align 3
_dtb:
