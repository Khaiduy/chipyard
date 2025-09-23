#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

/* Simple dummy entropy source for bare-metal RISC-V */
int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    for (word32 i = 0; i < sz; i++)
        output[i] = (byte)(i * 13 + 42);
    return 0;
}

