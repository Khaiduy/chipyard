#include <stdio.h>
//#include <riscv-pk/encoding.h>
//#include "marchid.h"

#define SERIAL 0x54000000

int main(void) {
  //uint64_t marchid = read_csr(marchid);
  //const char* march = get_march(marchid);
  //printf("Hello world from core 0, a %s\n", march);
  printf("Hello world from core 0\n");
//  int *serial;
//  serial  = SERIAL;
//  *serial = 1;
  return 0;
}
