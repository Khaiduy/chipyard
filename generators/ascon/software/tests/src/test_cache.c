#include <stdio.h>
#include <stdint.h>
#include "rocc.h"
#include "sha3.h"
#include "encoding.h"
#include "compiler.h"

#ifdef __linux
#include <sys/mman.h>
#endif

typedef union {
    uint64_t x[5];
    uint32_t w[5][2];
    uint8_t b[5][8];
} ascon_state_t;

int main() {
  unsigned long start, end;

    uint64_t state_1 = 0x80400C0600000000;
    uint64_t state_2 = 0x0001020304050607;
    uint64_t state_3 = 0x08090A0B0C0D0E0F;
    uint64_t state_4 = 0x0001020304050607;
    uint64_t state_5 = 0x08090A0B0C0D0E0F;
    uint8_t C = 0xC;
    
    ascon_state_t random_state;
    
    //asm volatile ("fence" ::: "memory");
    random_state.x[0] = state_1;
    random_state.x[1] = state_2;
    random_state.x[2] = state_3;
    random_state.x[3] = state_4;
    random_state.x[4] = state_5;
    
    uint32_t output[10] __aligned(4);
   
    /*for (int i = 0; i < 5; ++i) {
        printf("output[%d] = 0x%16llx\n", i, random_state.x[i]);
    }*/
    /*start = rdcycle();
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);

    C = 0xB;
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);
    
    C = 0xA;
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);
    C = 0x9;
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);
    C = 0x8;
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);
    C = 0x7;
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);
    C = 0x6;
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);
    C = 0x5;
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);
    C = 0x4;
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);
    C = 0x3;
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);
    C = 0x2;
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);
    C = 0x1;
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], &random_state.x[0], 6);
    ROCC_INSTRUCTION_S(1, C, 7);
    
    end = rdcycle();*/
    
    start = rdcycle();
    ROCC_INSTRUCTION_SS(1, &random_state.x[0], C, 6);
  
    end = rdcycle();
    
    asm volatile ("fence" ::: "memory");
    
    /*output[0] = random_state.w[0][0]; // Original value
    output[1] = random_state.w[0][1];
    output[2] = random_state.w[1][0];
    output[3] = random_state.w[1][1];
    output[4] = random_state.w[2][0];
    output[5] = random_state.w[2][1];
    output[6] = random_state.w[3][0];
    output[7] = random_state.w[3][1];
    output[8] = random_state.w[4][0];
    output[9] = random_state.w[4][1];*/
    
    for (int i = 0; i < 5; ++i) {
        printf("output[%d] = 0x%16llx\n", i, random_state.x[i]);
    }
    
    /*for (int i = 0; i < 10; ++i) {
        printf("output[%d] = 0x%08lx\n", i, output[i]);
    }*/

  //printf("Success!\n");
  printf("Permutation execution took %lu cycles\n", end - start);

  return 0;
}

