// See LICENSE.Sifive for license details.
#ifndef _SDBOOT_COMMON_H
#define _SDBOOT_COMMON_H

#ifndef PAYLOAD_DEST
  #define PAYLOAD_DEST MEMORY_MEM_ADDR
#endif

#ifndef STACK_SIZE
  #define STACK_SIZE 0x1ff0
#endif

#ifndef STACK_BASE
  #define STACK_BASE PAYLOAD_DEST
#endif


#endif
