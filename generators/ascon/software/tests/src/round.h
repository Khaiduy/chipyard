#ifndef ROUND_H_
#define ROUND_H_

#include "ascon.h"
#include "constants.h"
#include "forceinline.h"
#include "printstate.h"
#include "word.h"
//#include <stdio.h>
//#include "encoding.h"
#include "rocc.h"

forceinline void ROUND(ascon_state_t* s, uint8_t C) {
  uint64_t xtemp;
  
  /* round constant */
  s->x[2] ^= C;
  /* s-box layer */
  s->x[0] ^= s->x[4];
  s->x[4] ^= s->x[3];
  s->x[2] ^= s->x[1];
  xtemp = s->x[0] & ~s->x[4];
  s->x[0] ^= s->x[2] & ~s->x[1];
  s->x[2] ^= s->x[4] & ~s->x[3];
  s->x[4] ^= s->x[1] & ~s->x[0];
  s->x[1] ^= s->x[3] & ~s->x[2];
  s->x[3] ^= xtemp;
  s->x[1] ^= s->x[0];
  s->x[3] ^= s->x[2];
  s->x[0] ^= s->x[4];
  s->x[2] = ~s->x[2];
  /* linear layer */
  s->x[0] ^=
      (s->x[0] >> 19) ^ (s->x[0] << 45) ^ (s->x[0] >> 28) ^ (s->x[0] << 36);
  s->x[1] ^=
      (s->x[1] >> 61) ^ (s->x[1] << 3) ^ (s->x[1] >> 39) ^ (s->x[1] << 25);
  s->x[2] ^=
      (s->x[2] >> 1) ^ (s->x[2] << 63) ^ (s->x[2] >> 6) ^ (s->x[2] << 58);
  s->x[3] ^=
      (s->x[3] >> 10) ^ (s->x[3] << 54) ^ (s->x[3] >> 17) ^ (s->x[3] << 47);
  s->x[4] ^=
      (s->x[4] >> 7) ^ (s->x[4] << 57) ^ (s->x[4] >> 41) ^ (s->x[4] << 23);
  
  printstate(" round output", s);
}

#if ASCON_ROCC_PERMUTATION
void perform_rocc_instructions(uint8_t rcon, ascon_state_t *state) {

    ROCC_INSTRUCTION_SS(1, &state->w[0], rcon, 6);
    
}

forceinline void PROUNDS(ascon_state_t* s, int nr) {
  perform_rocc_instructions(nr, s);
  asm volatile ("fence" ::: "memory");
}

#else

//This is the original ROUND using software only
forceinline void PROUNDS(ascon_state_t* s, int nr) {
  int i = START(nr);  
  printf("Using the software permutation\n");
  do {
    ROUND(s, RC(i));
    i += INC;
  } while (i != END);
}



#endif

#endif /* ROUND_H_ */

/*forceinline void PROUNDS(ascon_state_t* s, int nr) {
  int i = START(nr);
  
  //printf("i = 0x%016x and nr = 0x%016x\n", i, nr);
  do {
    //printf("Print the original state:\n");
    //  for (int i = 0; i < 5; i++) {
    //  printf("x[%d] = 0x%016llx\n", i, s->x[i]);
    //}
    ascon_state_t temp_state = *s;
    ROUND(s, RC(i));
    i += INC;
    
    //printf("i = 0x%016x and nr = 0x%016x\n", i, nr);
    
    //printf("Software state:\n");
    //for (int i = 0; i < 5; i++) {
    //    printf("x[%d] = 0x%016llx\n", i, s->x[i]);
    //}
    
    //printf("And the temp state:\n");
    //for (int i = 0; i < 5; i++) {
    //  printf("x[%d] = 0x%016llx\n", i, temp_state.x[i]);
    //}
    //printf("State using RoCC:\n");
    perform_rocc_instructions(nr, &temp_state);
    nr--;
    //for (int i = 0; i < 5; i++) {
    //  printf("x[%d] = 0x%016llx\n", i, temp_state.x[i]);
    //}
    
    //Compare the state of RoCC and software
    for (int i = 0; i < 5; i++) {
    if(s->x[i] != temp_state.x[i])
      printf("Error\n");
    }   
    

    
    
  } while (i != END);
}
*/
