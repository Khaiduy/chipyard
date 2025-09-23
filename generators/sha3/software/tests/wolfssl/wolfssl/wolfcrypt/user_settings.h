/* user_settings.h - wolfSSL configuration for RISC-V with HASHDRBG */
#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* ------------------------------------------------------------------------- */
/* RNG Configuration */
/* ------------------------------------------------------------------------- */
#if 0
    /* Option 1: Bypass P-RNG and use only HW RNG */
    #define CUSTOM_RAND_TYPE      unsigned int
    extern int my_rng_gen_block(unsigned char* output, unsigned int sz);
    #undef  CUSTOM_RAND_GENERATE_BLOCK
    #define CUSTOM_RAND_GENERATE_BLOCK  my_rng_gen_block
#else
    /* Option 2: HASHDRBG with custom seed source (RECOMMENDED) */
    #define HAVE_HASHDRBG
    
    /* Custom seed configuration */
    #define CUSTOM_RAND_TYPE      unsigned int
    extern unsigned int my_rng_seed_gen(void);
    #undef  CUSTOM_RAND_GENERATE
    #define CUSTOM_RAND_GENERATE  my_rng_seed_gen
    
    /* HASHDRBG configuration */
    #define WC_RESEED_INTERVAL 10000  /* Reseed every 10000 requests */
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */