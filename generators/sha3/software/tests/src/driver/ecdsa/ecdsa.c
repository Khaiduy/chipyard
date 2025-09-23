#include "ecdsa.h"
#include <string.h>

#define MAX_TRIES 16
//#define DEBUG 1

#ifdef DEBUG
// #include <uart/uart.h>
#include <stdio.h>
#include <platform.h>
#include "fdt/fdt_sifive.h"
#endif
typedef unsigned int uint;

#if defined(__SIZEOF_INT128__) || ((__clang_major__ * 100 + __clang_minor__) >= 302)
    #define SUPPORTS_INT128 1
#else
    #define SUPPORTS_INT128 0
#endif

#if SUPPORTS_INT128
typedef unsigned __int128 uint128_t;
#else
typedef struct
{
    uint64_t m_low;
    uint64_t m_high;
} uint128_t;
#endif

typedef struct EccPoint
{
    uint64_t x[9];
    uint64_t y[9];
} EccPoint;

#define CONCAT1(a, b) a##b
#define CONCAT(a, b) CONCAT1(a, b)

uint64_t Curve_P_32[9] ={0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull, 0x0000000000000000ull, 0xFFFFFFFF00000001ull,0,0,0,0,0};
uint64_t Curve_P_48[9] ={0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,0,0,0};
uint64_t Curve_P_72[9] ={0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff};

uint64_t Curve_B_32[9] ={0x3BCE3C3E27D2604Bull, 0x651D06B0CC53B0F6ull, 0xB3EBBD55769886BCull, 0x5AC635D8AA3A93E7ull,0,0,0,0,0};
uint64_t Curve_B_48[9] ={0x2A85C8EDD3EC2AEF, 0xC656398D8A2ED19D, 0x0314088F5013875A, 0x181D9C6EFE814112, 0x988E056BE3F82D19, 0xB3312FA7E23EE7E4,0,0,0};
uint64_t Curve_B_72[9] ={0xef451fd46b503f00, 0x3573df883d2c34f1, 0x1652c0bd3bb1bf07, 0x56193951ec7e937b, 0xb8b489918ef109e1, 0xa2da725b99b315f3, 0x929a21a0b68540ee, 0x953eb9618e1c9a1f, 0x0000000000000051};

static EccPoint Curve_G_32 ={ \
    {0xF4A13945D898C296ull, 0x77037D812DEB33A0ull, 0xF8BCE6E563A440F2ull, 0x6B17D1F2E12C4247ull,0,0,0,0,0}, \
    {0xCBB6406837BF51F5ull, 0x2BCE33576B315ECEull, 0x8EE7EB4A7C0F9E16ull, 0x4FE342E2FE1A7F9Bull,0,0,0,0,0}};
static EccPoint Curve_G_48 ={ \
    {0x3A545E3872760AB7, 0x5502F25DBF55296C, 0x59F741E082542A38, 0x6E1D3B628BA79B98, 0x8EB1C71EF320AD74, 0xAA87CA22BE8B0537,0,0,0}, \
    {0x7A431D7C90EA0E5F, 0x0A60B1CE1D7E819D, 0xE9DA3113B5F0B8C0, 0xF8F41DBD289A147C, 0x5D9E98BF9292DC29, 0x3617DE4A96262C6F,0,0,0}};

static EccPoint Curve_G_72 ={ \
    {0xf97e7e31c2e5bd66, 0x3348b3c1856a429b, 0xfe1dc127a2ffa8de, 0xa14b5e77efe75928, 0xf828af606b4d3dba, 0x9c648139053fb521, 0x9e3ecb662395b442, 0x858e06b70404e9cd, 0x00c6}, \
    {0x88be94769fd16650, 0x353c7086a272c240, 0xc550b9013fad0761, 0x97ee72995ef42640, 0x17afbd17273e662c, 0x98f54449579b4468, 0x5c8a5fb42c7d1bd9, 0x39296a789a3bc004, 0x0118}};

uint64_t Curve_N_32[9] ={0xF3B9CAC2FC632551ull, 0xBCE6FAADA7179E84ull, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull,0,0,0,0,0};
uint64_t Curve_N_48[9] ={0xECEC196ACCC52973, 0x581A0DB248B0A77A, 0xC7634D81F4372DDF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,0,0,0};
uint64_t Curve_N_72[9] ={0xbb6fb71e91386409, 0x3bb5c9b8899c47ae, 0x7fcc0148f709a5d0, 0x51868783bf2f966b, 0xfffffffffffffffa, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,0x00000000000001ff};

/*static uint64_t curve_p[NUM_ECC_DIGITS] = CONCAT(Curve_P_, ECC_CURVE);
static uint64_t curve_b[NUM_ECC_DIGITS] = CONCAT(Curve_B_, ECC_CURVE);
static EccPoint curve_G = CONCAT(Curve_G_, ECC_CURVE);
static uint64_t curve_n[NUM_ECC_DIGITS] = CONCAT(Curve_N_, ECC_CURVE);*/

#if (defined(_WIN32) || defined(_WIN64))
/* Windows */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

static int getRandomNumber(uint64_t *p_vli)
{
    HCRYPTPROV l_prov;
    if(!CryptAcquireContext(&l_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        return 0;
    }

    CryptGenRandom(l_prov, ECC_BYTES, (BYTE *)p_vli);
    CryptReleaseContext(l_prov, 0);
    
    return 1;
}

#else /* _WIN32 */

/* Assume that we are using a POSIX-like system with /dev/urandom or /dev/random. */
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
    #define O_CLOEXEC 0
#endif
//TODO: change for real trng
/*static int getRandomNumber(uint64_t *p_vli)
{
    int l_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if(l_fd == -1)
    {
        l_fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
        if(l_fd == -1)
        {
            return 0;
        }
    }
    
    char *l_ptr = (char *)p_vli;
    size_t l_left = ECC_BYTES;
    while(l_left > 0)
    {
        int l_read = read(l_fd, l_ptr, l_left);
        if(l_read <= 0)
        { // read failed
            close(l_fd);
            return 0;
        }
        l_left -= l_read;
        l_ptr += l_read;
    }
    
    close(l_fd);
    return 1;
}*/

#endif /* _WIN32 */

static void vli_clear(uint8_t curve, uint64_t *p_vli)
{
    uint i;
    for(i=0; i<(curve>>3); ++i)
    {
        p_vli[i] = 0;
    }
}

/* Returns 1 if p_vli == 0, 0 otherwise. */
static int vli_isZero(uint8_t curve, uint64_t *p_vli)
{
    uint i;
    for(i = 0; i < (curve>>3); ++i)
    {
        if(p_vli[i])
        {
            return 0;
        }
    }
    return 1;
}

/* Returns nonzero if bit p_bit of p_vli is set. */
static uint64_t vli_testBit(uint64_t *p_vli, uint p_bit)
{
    return (p_vli[p_bit/64] & ((uint64_t)1 << (p_bit % 64)));
}

/* Counts the number of 64-bit "digits" in p_vli. */
static uint vli_numDigits(uint8_t curve, uint64_t *p_vli)
{
    int i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for(i = (curve>>3) - 1; i >= 0 && p_vli[i] == 0; --i)
    {
    }

    return (i + 1);
}

/* Counts the number of bits required for p_vli. */
static uint vli_numBits(uint8_t curve, uint64_t *p_vli)
{
    uint i;
    uint64_t l_digit;
    
    uint l_numDigits = vli_numDigits(curve, p_vli);
    if(l_numDigits == 0)
    {
        return 0;
    }

    l_digit = p_vli[l_numDigits - 1];
    for(i=0; l_digit; ++i)
    {
        l_digit >>= 1;
    }
    
    return ((l_numDigits - 1) * 64 + i);
}

/* Sets p_dest = p_src. */
static void vli_set(uint8_t curve, uint64_t *p_dest, uint64_t *p_src)
{
    uint i;
    for(i=0; i<(curve>>3); ++i)
    {
        p_dest[i] = p_src[i];
    }
}

/* Returns sign of p_left - p_right. */
static int vli_cmp(uint8_t curve, uint64_t *p_left, uint64_t *p_right)
{
    int i;
    for(i = (curve>>3)-1; i >= 0; --i)
    {
        if(p_left[i] > p_right[i])
        {
            return 1;
        }
        else if(p_left[i] < p_right[i])
        {
            return -1;
        }
    }
    return 0;
}

/* Computes p_result = p_in << c, returning carry. Can modify in place (if p_result == p_in). 0 < p_shift < 64. */
static uint64_t vli_lshift(uint8_t curve, uint64_t *p_result, uint64_t *p_in, uint p_shift)
{
    uint64_t l_carry = 0;
    uint i;
    for(i = 0; i < curve>>3; ++i)
    {
        uint64_t l_temp = p_in[i];
        p_result[i] = (l_temp << p_shift) | l_carry;
        l_carry = l_temp >> (64 - p_shift);
    }
    
    return l_carry;
}

/* Computes p_vli = p_vli >> 1. */
static void vli_rshift1(uint8_t curve, uint64_t *p_vli)
{
    uint64_t *l_end = p_vli;
    uint64_t l_carry = 0;
    
    p_vli += (curve>>3);
    while(p_vli-- > l_end)
    {
        uint64_t l_temp = *p_vli;
        *p_vli = (l_temp >> 1) | l_carry;
        l_carry = l_temp << 63;
    }
}

/* Computes p_result = p_left + p_right, returning carry. Can modify in place. */
static uint64_t vli_add(uint8_t curve, uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint64_t l_carry = 0;
    uint i;
    for(i=0; i<(curve>>3); ++i)
    {
        uint64_t l_sum = p_left[i] + p_right[i] + l_carry;
        if(l_sum != p_left[i])
        {
            l_carry = (l_sum < p_left[i]);
        }
        p_result[i] = l_sum;
    }
    return l_carry;
}

/* Computes p_result = p_left - p_right, returning borrow. Can modify in place. */
static uint64_t vli_sub(uint8_t curve, uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint64_t l_borrow = 0;
    uint i;
    for(i=0; i<(curve>>3); ++i)
    {
        uint64_t l_diff = p_left[i] - p_right[i] - l_borrow;
        if(l_diff != p_left[i])
        {
            l_borrow = (l_diff > p_left[i]);
        }
        p_result[i] = l_diff;
    }
    return l_borrow;
}

#if SUPPORTS_INT128

/* Computes p_result = p_left * p_right. */
static void vli_mult(uint8_t curve, uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint128_t r01 = 0;
    uint64_t r2 = 0;
    
    uint i, k;
    
    /* Compute each digit of p_result in sequence, maintaining the carries. */
    for(k=0; k < (curve>>3)*2 - 1; ++k)
    {
        uint l_min = (k < (curve>>3) ? 0 : (k + 1) - (curve>>3));
        for(i=l_min; i<=k && i<(curve>>3); ++i)
        {
            uint128_t l_product = (uint128_t)p_left[i] * p_right[k-i];
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint64_t)r01;
        r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
        r2 = 0;
    }
    
    p_result[(curve>>3)*2 - 1] = (uint64_t)r01;
}

/* Computes p_result = p_left^2. */
static void vli_square(uint8_t curve, uint64_t *p_result, uint64_t *p_left)
{
    uint128_t r01 = 0;
    uint64_t r2 = 0;
    
    uint i, k;
    for(k=0; k < (curve>>3)*2 - 1; ++k)
    {
        uint l_min = (k < (curve>>3) ? 0 : (k + 1) - (curve>>3));
        for(i=l_min; i<=k && i<=k-i; ++i)
        {
            uint128_t l_product = (uint128_t)p_left[i] * p_left[k-i];
            if(i < k-i)
            {
                r2 += l_product >> 127;
                l_product *= 2;
            }
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint64_t)r01;
        r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
        r2 = 0;
    }
    
    p_result[(curve>>3)*2 - 1] = (uint64_t)r01;
}

#else /* #if SUPPORTS_INT128 */

static uint128_t mul_64_64(uint64_t p_left, uint64_t p_right)
{
    uint128_t l_result;
    
    uint64_t a0 = p_left & 0xffffffffull;
    uint64_t a1 = p_left >> 32;
    uint64_t b0 = p_right & 0xffffffffull;
    uint64_t b1 = p_right >> 32;
    
    uint64_t m0 = a0 * b0;
    uint64_t m1 = a0 * b1;
    uint64_t m2 = a1 * b0;
    uint64_t m3 = a1 * b1;
    
    m2 += (m0 >> 32);
    m2 += m1;
    if(m2 < m1)
    { // overflow
        m3 += 0x100000000ull;
    }
    
    l_result.m_low = (m0 & 0xffffffffull) | (m2 << 32);
    l_result.m_high = m3 + (m2 >> 32);
    
    return l_result;
}

static uint128_t add_128_128(uint128_t a, uint128_t b)
{
    uint128_t l_result;
    l_result.m_low = a.m_low + b.m_low;
    l_result.m_high = a.m_high + b.m_high + (l_result.m_low < a.m_low);
    return l_result;
}

static void vli_mult(uint8_t curve, uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint128_t r01 = {0, 0};
    uint64_t r2 = 0;
    
    uint i, k;
    
    /* Compute each digit of p_result in sequence, maintaining the carries. */
    for(k=0; k < (curve>>3)*2 - 1; ++k)
    {
        uint l_min = (k < (curve>>3) ? 0 : (k + 1) - (curve>>3));
        for(i=l_min; i<=k && i<(curve>>3); ++i)
        {
            uint128_t l_product = mul_64_64(p_left[i], p_right[k-i]);
            r01 = add_128_128(r01, l_product);
            r2 += (r01.m_high < l_product.m_high);
        }
        p_result[k] = r01.m_low;
        r01.m_low = r01.m_high;
        r01.m_high = r2;
        r2 = 0;
    }
    
    p_result[(curve>>3)*2 - 1] = r01.m_low;
}

static void vli_square(uint8_t curve, uint64_t *p_result, uint64_t *p_left)
{
    uint128_t r01 = {0, 0};
    uint64_t r2 = 0;
    
    uint i, k;
    for(k=0; k < (curve>>3)*2 - 1; ++k)
    {
        uint l_min = (k < (curve>>3) ? 0 : (k + 1) - (curve>>3));
        for(i=l_min; i<=k && i<=k-i; ++i)
        {
            uint128_t l_product = mul_64_64(p_left[i], p_left[k-i]);
            if(i < k-i)
            {
                r2 += l_product.m_high >> 63;
                l_product.m_high = (l_product.m_high << 1) | (l_product.m_low >> 63);
                l_product.m_low <<= 1;
            }
            r01 = add_128_128(r01, l_product);
            r2 += (r01.m_high < l_product.m_high);
        }
        p_result[k] = r01.m_low;
        r01.m_low = r01.m_high;
        r01.m_high = r2;
        r2 = 0;
    }
    
    p_result[(curve>>3)*2 - 1] = r01.m_low;
}

#endif /* SUPPORTS_INT128 */


/* Computes p_result = (p_left + p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modAdd(uint8_t curve, uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
    uint64_t l_carry = vli_add(curve,p_result, p_left, p_right);
    if(l_carry || vli_cmp(curve,p_result, p_mod) >= 0)
    { /* p_result > p_mod (p_result = p_mod + remainder), so subtract p_mod to get remainder. */
        vli_sub(curve,p_result, p_result, p_mod);
    }
}

/* Computes p_result = (p_left - p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modSub(uint8_t curve, uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
    uint64_t l_borrow = vli_sub(curve,p_result, p_left, p_right);
    if(l_borrow)
    { /* In this case, p_result == -diff == (max int) - diff.
         Since -x % d == d - x, we can get the correct result from p_result + p_mod (with overflow). */
        vli_add(curve,p_result, p_result, p_mod);
    }
}

//for 386 curve
static void omega_mult(uint64_t *p_result, uint64_t *p_right)
{
    uint64_t l_tmp[6];
    uint64_t l_carry, l_diff;
    
    /* Multiply by (2^128 + 2^96 - 2^32 + 1). */
    vli_set(secp384r1,p_result, p_right); /* 1 */
    l_carry = vli_lshift(secp384r1,l_tmp, p_right, 32);
    p_result[1 + 6] = l_carry + vli_add(secp384r1,p_result + 1, p_result + 1, l_tmp); /* 2^96 + 1 */
    p_result[2 + 6] = vli_add(secp384r1,p_result + 2, p_result + 2, p_right); /* 2^128 + 2^96 + 1 */
    l_carry += vli_sub(secp384r1,p_result, p_result, l_tmp); /* 2^128 + 2^96 - 2^32 + 1 */
    l_diff = p_result[6] - l_carry;
    if(l_diff > p_result[6])
    { /* Propagate borrow if necessary. */
        uint i;
        for(i = 1 + 6; ; ++i)
        {
            --p_result[i];
            if(p_result[i] != (uint64_t)-1)
            {
                break;
            }
        }
    }
    p_result[6] = l_diff;
}


// Computes p_result = p_product % curve_p
// from http://www.nsa.gov/ia/_files/nist-routines.pdf
static void vli_mmod_fast(uint8_t curve, uint64_t *p_result, uint64_t *p_product){
if(curve == secp256r1)
{
    uint64_t l_tmp[32>>3];
    int l_carry;
    
    // t
    vli_set(curve, p_result, p_product);
    
    // s1 
    l_tmp[0] = 0;
    l_tmp[1] = p_product[5] & 0xffffffff00000000ull;
    l_tmp[2] = p_product[6];
    l_tmp[3] = p_product[7];
    l_carry = vli_lshift(curve, l_tmp, l_tmp, 1);
    l_carry += vli_add(curve, p_result, p_result, l_tmp);
    
    // s2 
    l_tmp[1] = p_product[6] << 32;
    l_tmp[2] = (p_product[6] >> 32) | (p_product[7] << 32);
    l_tmp[3] = p_product[7] >> 32;
    l_carry += vli_lshift(curve, l_tmp, l_tmp, 1);
    l_carry += vli_add(curve, p_result, p_result, l_tmp);
    
    // s3
    l_tmp[0] = p_product[4];
    l_tmp[1] = p_product[5] & 0xffffffff;
    l_tmp[2] = 0;
    l_tmp[3] = p_product[7];
    l_carry += vli_add(curve, p_result, p_result, l_tmp);
    
    // s4
    l_tmp[0] = (p_product[4] >> 32) | (p_product[5] << 32);
    l_tmp[1] = (p_product[5] >> 32) | (p_product[6] & 0xffffffff00000000ull);
    l_tmp[2] = p_product[7];
    l_tmp[3] = (p_product[6] >> 32) | (p_product[4] << 32);
    l_carry += vli_add(curve, p_result, p_result, l_tmp);
    
    // d1 
    l_tmp[0] = (p_product[5] >> 32) | (p_product[6] << 32);
    l_tmp[1] = (p_product[6] >> 32);
    l_tmp[2] = 0;
    l_tmp[3] = (p_product[4] & 0xffffffff) | (p_product[5] << 32);
    l_carry -= vli_sub(curve, p_result, p_result, l_tmp);
    
    // d2 
    l_tmp[0] = p_product[6];
    l_tmp[1] = p_product[7];
    l_tmp[2] = 0;
    l_tmp[3] = (p_product[4] >> 32) | (p_product[5] & 0xffffffff00000000ull);
    l_carry -= vli_sub(curve, p_result, p_result, l_tmp);
    
    // d3 
    l_tmp[0] = (p_product[6] >> 32) | (p_product[7] << 32);
    l_tmp[1] = (p_product[7] >> 32) | (p_product[4] << 32);
    l_tmp[2] = (p_product[4] >> 32) | (p_product[5] << 32);
    l_tmp[3] = (p_product[6] << 32);
    l_carry -= vli_sub(curve, p_result, p_result, l_tmp);
    
    // d4 
    l_tmp[0] = p_product[7];
    l_tmp[1] = p_product[4] & 0xffffffff00000000ull;
    l_tmp[2] = p_product[5];
    l_tmp[3] = p_product[6] & 0xffffffff00000000ull;
    l_carry -= vli_sub(curve, p_result, p_result, l_tmp);
    
    if(l_carry < 0)
    {
        do
        {
            l_carry += vli_add(curve, p_result, p_result, Curve_P_32);
        } while(l_carry < 0);
    }
    else
    {
        while(l_carry || vli_cmp(curve, Curve_P_32, p_result) != 1)
        {
            l_carry -= vli_sub(curve, p_result, p_result, Curve_P_32);
        }
    }
}

else if (curve == secp384r1)
/* Computes p_result = p_product % curve_p
    see PDF "Comparing Elliptic Curve Cryptography and RSA on 8-bit CPUs"
    section "Curve-Specific Optimizations" */
//static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[2*6];
     
    while(!vli_isZero(curve, p_product + 6)) /* While c1 != 0 */
    {
        uint64_t l_carry = 0;
        uint i;
        
        vli_clear(curve, l_tmp);
        vli_clear(curve, l_tmp + 6);
        omega_mult(l_tmp, p_product + 6); /* tmp = w * c1 */
        vli_clear(curve, p_product + 6); /* p = c0 */
        
        /* (c1, c0) = c0 + w * c1 */
        for(i=0; i<6+3; ++i)
        {
            uint64_t l_sum = p_product[i] + l_tmp[i] + l_carry;
            if(l_sum != p_product[i])
            {
                l_carry = (l_sum < p_product[i]);
            }
            p_product[i] = l_sum;
        }
    }
    
    while(vli_cmp(curve, p_product, Curve_P_48) > 0)
    {
        vli_sub(curve, p_product, p_product, Curve_P_48);
    }
    vli_set(curve, p_result, p_product);
}
else if (curve == secp521r1)
//static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[9];

    // t
    vli_set(curve,p_result, p_product);
    p_result[8] &= 0x1FF;
    
    // s
    l_tmp[0] =   (p_product[9]<<(64-9)) | (p_product[8]>>9);
    l_tmp[1] =   (p_product[10]<<(64-9)) | (p_product[9]>>9);
    l_tmp[2] =   (p_product[11]<<(64-9)) | (p_product[10]>>9);
    l_tmp[3] =   (p_product[12]<<(64-9)) | (p_product[11]>>9);
    l_tmp[4] =   (p_product[13]<<(64-9)) | (p_product[12]>>9);
    l_tmp[5] =   (p_product[14]<<(64-9)) | (p_product[13]>>9);
    l_tmp[6] =   (p_product[15]<<(64-9)) | (p_product[14]>>9);
    l_tmp[7] =   (p_product[16]<<(64-9)) | (p_product[15]>>9);
    l_tmp[8] = ((p_product[17]<<(64-9)) | (p_product[16]>>9)) & 0x1FF;

    vli_add(curve, p_result, l_tmp, p_result);

    while(vli_cmp(curve, Curve_P_72, p_result)!=1)
    {
        vli_sub(curve, p_result, p_result, Curve_P_72);
    }
}
}

/* Computes p_result = (p_left * p_right) % curve_p. */
static void vli_modMult_fast(uint8_t curve, uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint64_t l_product[18];
    vli_mult(curve, l_product, p_left, p_right);
    vli_mmod_fast(curve, p_result, l_product);
}

/* Computes p_result = p_left^2 % curve_p. */
static void vli_modSquare_fast(uint8_t curve, uint64_t *p_result, uint64_t *p_left)
{
    uint64_t l_product[18];
    vli_square(curve, l_product, p_left);
    vli_mmod_fast(curve, p_result, l_product);
}

#define EVEN(vli) (!(vli[0] & 1))
/* Computes p_result = (1 / p_input) % p_mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
   https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf */
static void vli_modInv(uint8_t curve, uint64_t *p_result, uint64_t *p_input, uint64_t *p_mod)
{
    uint64_t a[9], b[9], u[9], v[9];
    uint64_t l_carry;
    int l_cmpResult;
    
    if(vli_isZero(curve, p_input))
    {
        vli_clear(curve, p_result);
        return;
    }

    vli_set(curve, a, p_input);
    vli_set(curve, b, p_mod);
    vli_clear(curve, u);
    u[0] = 1;
    vli_clear(curve, v);
    
    while((l_cmpResult = vli_cmp(curve, a, b)) != 0)
    {
        l_carry = 0;
        if(EVEN(a))
        {
            vli_rshift1(curve, a);
            if(!EVEN(u))
            {
                l_carry = vli_add(curve, u, u, p_mod);
            }
            vli_rshift1(curve, u);
            if(l_carry)
            {
                u[(curve>>3)-1] |= 0x8000000000000000ull;
            }
        }
        else if(EVEN(b))
        {
            vli_rshift1(curve, b);
            if(!EVEN(v))
            {
                l_carry = vli_add(curve, v, v, p_mod);
            }
            vli_rshift1(curve, v);
            if(l_carry)
            {
                v[(curve>>3)-1] |= 0x8000000000000000ull;
            }
        }
        else if(l_cmpResult > 0)
        {
            vli_sub(curve, a, a, b);
            vli_rshift1(curve, a);
            if(vli_cmp(curve, u, v) < 0)
            {
                vli_add(curve, u, u, p_mod);
            }
            vli_sub(curve, u, u, v);
            if(!EVEN(u))
            {
                l_carry = vli_add(curve, u, u, p_mod);
            }
            vli_rshift1(curve, u);
            if(l_carry)
            {
                u[(curve>>3)-1] |= 0x8000000000000000ull;
            }
        }
        else
        {
            vli_sub(curve, b, b, a);
            vli_rshift1(curve, b);
            if(vli_cmp(curve, v, u) < 0)
            {
                vli_add(curve, v, v, p_mod);
            }
            vli_sub(curve, v, v, u);
            if(!EVEN(v))
            {
                l_carry = vli_add(curve, v, v, p_mod);
            }
            vli_rshift1(curve, v);
            if(l_carry)
            {
                v[(curve>>3)-1] |= 0x8000000000000000ull;
            }
        }
    }
    
    vli_set(curve, p_result, u);
}

/* ------ Point operations ------ */

/* Returns 1 if p_point is the point at infinity, 0 otherwise. */
static int EccPoint_isZero(uint8_t curve, EccPoint *p_point)
{
    return (vli_isZero(curve, p_point->x) && vli_isZero(curve, p_point->y));
}

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
From http://eprint.iacr.org/2011/338.pdf
*/

/* Double in place */
static void EccPoint_double_jacobian(uint8_t curve, uint64_t *X1, uint64_t *Y1, uint64_t *Z1)
{
    /* t1 = X, t2 = Y, t3 = Z */
    uint64_t t4[9];
    uint64_t t5[9];
    
    if(vli_isZero(curve, Z1))
    {
        return;
    }
    uint64_t * curve_p;
    if(curve == secp256r1)
    {curve_p = Curve_P_32;}
    else if (curve == secp384r1)
    {curve_p = Curve_P_48;}
    else if (curve == secp521r1)
    {curve_p = Curve_P_72;}
    else 
    {curve_p = Curve_P_32;}

    vli_modSquare_fast(curve, t4, Y1);   /* t4 = y1^2 */
    vli_modMult_fast(curve, t5, X1, t4); /* t5 = x1*y1^2 = A */
    vli_modSquare_fast(curve, t4, t4);   /* t4 = y1^4 */
    vli_modMult_fast(curve, Y1, Y1, Z1); /* t2 = y1*z1 = z3 */
    vli_modSquare_fast(curve, Z1, Z1);   /* t3 = z1^2 */
    
    vli_modAdd(curve, X1, X1, Z1, curve_p); /* t1 = x1 + z1^2 */
    vli_modAdd(curve, Z1, Z1, Z1, curve_p); /* t3 = 2*z1^2 */
    vli_modSub(curve, Z1, X1, Z1, curve_p); /* t3 = x1 - z1^2 */
    vli_modMult_fast(curve, X1, X1, Z1);    /* t1 = x1^2 - z1^4 */
    
    vli_modAdd(curve, Z1, X1, X1, curve_p); /* t3 = 2*(x1^2 - z1^4) */
    vli_modAdd(curve, X1, X1, Z1, curve_p); /* t1 = 3*(x1^2 - z1^4) */
    if(vli_testBit(X1, 0))
    {
        uint64_t l_carry = vli_add(curve, X1, X1, curve_p);
        vli_rshift1(curve, X1);
        X1[(curve>>3)-1] |= l_carry << 63;
    }
    else
    {
        vli_rshift1(curve, X1);
    }
    /* t1 = 3/2*(x1^2 - z1^4) = B */
    
    vli_modSquare_fast(curve, Z1, X1);      /* t3 = B^2 */
    vli_modSub(curve, Z1, Z1, t5, curve_p); /* t3 = B^2 - A */
    vli_modSub(curve, Z1, Z1, t5, curve_p); /* t3 = B^2 - 2A = x3 */
    vli_modSub(curve, t5, t5, Z1, curve_p); /* t5 = A - x3 */
    vli_modMult_fast(curve, X1, X1, t5);    /* t1 = B * (A - x3) */
    vli_modSub(curve, t4, X1, t4, curve_p); /* t4 = B * (A - x3) - y1^4 = y3 */
    
    vli_set(curve, X1, Z1);
    vli_set(curve, Z1, Y1);
    vli_set(curve, Y1, t4);
}

// Modify (x1, y1) => (x1 * z^2, y1 * z^3) 
static void apply_z(uint8_t curve, uint64_t *X1, uint64_t *Y1, uint64_t *Z)
{
    uint64_t t1[9];

    vli_modSquare_fast(curve, t1, Z);    // z^2 
    vli_modMult_fast(curve, X1, X1, t1); // x1 * z^2 
    vli_modMult_fast(curve, t1, t1, Z);  // z^3 
    vli_modMult_fast(curve, Y1, Y1, t1); // y1 * z^3
}

// P = (x1, y1) => 2P, (x2, y2) => P' 
static void XYcZ_initial_double(uint8_t curve, uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2, uint64_t *p_initialZ)
{
    uint64_t z[9];
    
    vli_set(curve, X2, X1);
    vli_set(curve, Y2, Y1);
    
    vli_clear(curve, z);
    z[0] = 1;
    if(p_initialZ)
    {
        vli_set(curve, z, p_initialZ);
    }

    apply_z(curve, X1, Y1, z);
    
    EccPoint_double_jacobian(curve, X1, Y1, z);
    
    apply_z(curve, X2, Y2, z);
}

// Input P = (x1, y1, Z), Q = (x2, y2, Z)
//   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
//   or P => P', Q => P + Q
//
static void XYcZ_add(uint8_t curve, uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    
    uint64_t t5[9];
    uint64_t * curve_p;
    if(curve == secp256r1)
    {curve_p = Curve_P_32;}
    else if (curve == secp384r1)
    {curve_p = Curve_P_48;}
    else if (curve == secp521r1)
    {curve_p = Curve_P_72;}
    else 
    {curve_p = Curve_P_32;}

    vli_modSub(curve, t5, X2, X1, curve_p); /* t5 = x2 - x1 */
    vli_modSquare_fast(curve, t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(curve, X1, X1, t5);    /* t1 = x1*A = B */
    vli_modMult_fast(curve, X2, X2, t5);    /* t3 = x2*A = C */
    vli_modSub(curve, Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */
    vli_modSquare_fast(curve, t5, Y2);      /* t5 = (y2 - y1)^2 = D */
    
    vli_modSub(curve, t5, t5, X1, curve_p); /* t5 = D - B */
    vli_modSub(curve, t5, t5, X2, curve_p); /* t5 = D - B - C = x3 */
    vli_modSub(curve, X2, X2, X1, curve_p); /* t3 = C - B */
    vli_modMult_fast(curve, Y1, Y1, X2);    /* t2 = y1*(C - B) */
    vli_modSub(curve, X2, X1, t5, curve_p); /* t3 = B - x3 */
    vli_modMult_fast(curve, Y2, Y2, X2);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub(curve, Y2, Y2, Y1, curve_p); /* t4 = y3 */
    
    vli_set(curve, X2, t5);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
static void XYcZ_addC(uint8_t curve, uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uint64_t t5[9];
    uint64_t t6[9];
    uint64_t t7[9];
    
    uint64_t * curve_p;
    if(curve == secp256r1)
    {curve_p = Curve_P_32;}
    else if (curve == secp384r1)
    {curve_p = Curve_P_48;}
    else if (curve == secp521r1)
    {curve_p = Curve_P_72;}
    else 
    {curve_p = Curve_P_32;}

    vli_modSub(curve, t5, X2, X1, curve_p); /* t5 = x2 - x1 */
    vli_modSquare_fast(curve, t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(curve, X1, X1, t5);    /* t1 = x1*A = B */
    vli_modMult_fast(curve, X2, X2, t5);    /* t3 = x2*A = C */
    vli_modAdd(curve, t5, Y2, Y1, curve_p); /* t4 = y2 + y1 */
    vli_modSub(curve, Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */

    vli_modSub(curve, t6, X2, X1, curve_p); /* t6 = C - B */
    vli_modMult_fast(curve, Y1, Y1, t6);    /* t2 = y1 * (C - B) */
    vli_modAdd(curve, t6, X1, X2, curve_p); /* t6 = B + C */
    vli_modSquare_fast(curve, X2, Y2);      /* t3 = (y2 - y1)^2 */
    vli_modSub(curve, X2, X2, t6, curve_p); /* t3 = x3 */
    
    vli_modSub(curve, t7, X1, X2, curve_p); /* t7 = B - x3 */
    vli_modMult_fast(curve, Y2, Y2, t7);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub(curve, Y2, Y2, Y1, curve_p); /* t4 = y3 */
    
    vli_modSquare_fast(curve, t7, t5);      /* t7 = (y2 + y1)^2 = F */
    vli_modSub(curve, t7, t7, t6, curve_p); /* t7 = x3' */
    vli_modSub(curve, t6, t7, X1, curve_p); /* t6 = x3' - B */
    vli_modMult_fast(curve, t6, t6, t5);    /* t6 = (y2 + y1)*(x3' - B) */
    vli_modSub(curve, Y1, t6, Y1, curve_p); /* t2 = y3' */
    
    vli_set(curve, X1, t7);
}

static void EccPoint_mult(uint8_t curve, EccPoint *p_result, EccPoint *p_point, uint64_t *p_scalar, uint64_t *p_initialZ)
{
    /* R0 and R1 */
    uint64_t Rx[2][9];
    uint64_t Ry[2][9];
    uint64_t z[9];
    
    int i, nb;
    
    vli_set(curve, Rx[1], p_point->x);
    vli_set(curve, Ry[1], p_point->y);

    XYcZ_initial_double(curve, Rx[1], Ry[1], Rx[0], Ry[0], p_initialZ);

    for(i = vli_numBits(curve, p_scalar) - 2; i > 0; --i)
    {
        nb = !vli_testBit(p_scalar, i);
        XYcZ_addC(curve, Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
        XYcZ_add(curve, Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
    }

    nb = !vli_testBit(p_scalar, 0);
    XYcZ_addC(curve, Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
    
    uint64_t * curve_p;
    if(curve == secp256r1)
    {curve_p = Curve_P_32;}
    else if (curve == secp384r1)
    {curve_p = Curve_P_48;}
    else if (curve == secp521r1)
    {curve_p = Curve_P_72;}
    else 
    {curve_p = Curve_P_32;}

    // Find final 1/Z value. //
    vli_modSub(curve, z, Rx[1], Rx[0], curve_p); // X1 - X0 
    vli_modMult_fast(curve, z, z, Ry[1-nb]);     // Yb * (X1 - X0) 
    vli_modMult_fast(curve, z, z, p_point->x);   // xP * Yb * (X1 - X0) 
    vli_modInv(curve, z, z, curve_p);            // 1 / (xP * Yb * (X1 - X0)) 
    vli_modMult_fast(curve, z, z, p_point->y);   // yP / (xP * Yb * (X1 - X0)) 
    vli_modMult_fast(curve, z, z, Rx[1-nb]);     // Xb * yP / (xP * Yb * (X1 - X0)) 
    // End 1/Z calculation //

    XYcZ_add(curve, Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
    
    apply_z(curve, Rx[0], Ry[0], z);
    
    vli_set(curve, p_result->x, Rx[0]);
    vli_set(curve, p_result->y, Ry[0]);
}

static void ecc_bytes2native(uint8_t curve, uint64_t * p_native, const uint8_t * p_bytes)
{
    unsigned i;
    for(i=0; i<(curve>>3); ++i)
    {
        const uint8_t *p_digit = p_bytes + 8 * ((curve>>3) - 1 - i);
        p_native[i] = ((uint64_t)p_digit[0] << 56) | ((uint64_t)p_digit[1] << 48) | ((uint64_t)p_digit[2] << 40) | ((uint64_t)p_digit[3] << 32) |
            ((uint64_t)p_digit[4] << 24) | ((uint64_t)p_digit[5] << 16) | ((uint64_t)p_digit[6] << 8) | (uint64_t)p_digit[7];
    }
}

void ecc_native2bytes(uint8_t curve, uint8_t * p_bytes, const uint64_t * p_native)
{
    unsigned i;
    for(i=0; i<(curve>>3); ++i)
    {
        uint8_t *p_digit = p_bytes + 8 * ((curve>>3) - 1 - i);
        p_digit[0] = p_native[i] >> 56;
        p_digit[1] = p_native[i] >> 48;
        p_digit[2] = p_native[i] >> 40;
        p_digit[3] = p_native[i] >> 32;
        p_digit[4] = p_native[i] >> 24;
        p_digit[5] = p_native[i] >> 16;
        p_digit[6] = p_native[i] >> 8;
        p_digit[7] = p_native[i];
    }
}

/* Compute a = sqrt(a) (mod curve_p). */
static void mod_sqrt(uint8_t curve, uint64_t * a)
{
    unsigned i;
    uint64_t p1[9] = {1};
    uint64_t l_result[9] = {1};
    
    uint64_t * curve_p;
    if(curve == secp256r1)
    {curve_p = Curve_P_32;}
    else if (curve == secp384r1)
    {curve_p = Curve_P_48;}
    else if (curve == secp521r1)
    {curve_p = Curve_P_72;}
    else 
    {curve_p = Curve_P_32;}

    /* Since curve_p == 3 (mod 4) for all supported curves, we can
       compute sqrt(a) = a^((curve_p + 1) / 4) (mod curve_p). */
    vli_add(curve, p1, curve_p, p1); /* p1 = curve_p + 1 */
    for(i = vli_numBits(curve, p1) - 1; i > 1; --i)
    {
        vli_modSquare_fast(curve, l_result, l_result);
        if(vli_testBit(p1, i))
        {
            vli_modMult_fast(curve, l_result, l_result, a);
        }
    }
    vli_set(curve, a, l_result);
}

static void ecc_point_decompress(uint8_t curve, EccPoint *p_point, const uint8_t * p_compressed)
{
    uint64_t _3[9] = {3}; /* -a = 3 */
    ecc_bytes2native(curve, p_point->x, p_compressed+1);
    
    uint64_t * curve_p;
    uint64_t * curve_b;
    if(curve == secp256r1)
    {curve_p = Curve_P_32;curve_b = Curve_B_32;}
    else if (curve == secp384r1)
    {curve_p = Curve_P_48;curve_b = Curve_B_48;}
    else if (curve == secp521r1)
    {curve_p = Curve_P_72;curve_b = Curve_B_72;}
    else 
    {curve_p = Curve_P_32;curve_b = Curve_B_32;}

    vli_modSquare_fast(curve, p_point->y, p_point->x); /* y = x^2 */
    vli_modSub(curve, p_point->y, p_point->y, _3, curve_p); /* y = x^2 - 3 */
    vli_modMult_fast(curve, p_point->y, p_point->y, p_point->x); /* y = x^3 - 3x */
    vli_modAdd(curve, p_point->y, p_point->y, curve_b, curve_p); /* y = x^3 - 3x + b */
    
    mod_sqrt(curve, p_point->y);
    
    if((p_point->y[0] & 0x01) != (p_compressed[0] & 0x01))
    {
        vli_sub(curve, p_point->y, curve_p, p_point->y);
    }
}

int ecc_make_key(uint8_t curve, uint8_t * p_publicKey, uint8_t * p_privateKey, uint64_t * l_private )
{
    EccPoint l_public;
    //unsigned l_tries = 0;

    EccPoint curve_g;
    uint64_t * curve_n;
    if(curve == secp256r1)
    {curve_g = Curve_G_32;curve_n = Curve_N_32;}
    else if (curve == secp384r1)
    {curve_g = Curve_G_48;curve_n = Curve_N_48;}
    else if (curve == secp521r1)
    {curve_g = Curve_G_72;curve_n = Curve_N_72;}
    else 
    {curve_g = Curve_G_32;curve_n = Curve_N_32;}

    vli_isZero(curve, l_private);
    EccPoint_mult(curve, &l_public, &curve_g, l_private, NULL);
    //TODO: verify randon number outside
    do
    {
        //if(!getRandomNumber(l_private) || (l_tries++ >= MAX_TRIES))
        //{
        //  return 0;
        //}
        if(vli_isZero(curve, l_private))
        {
            continue;
        }
    
        // Make sure the private key is in the range [1, n-1].
        // For the supported curves, n is always large enough that we only need to subtract once at most.
        if(vli_cmp(curve, curve_n, l_private) != 1)
        {
            vli_sub(curve, l_private, l_private, curve_n);
        }
        EccPoint_mult(curve, &l_public, &curve_g, l_private, NULL);
    } while(EccPoint_isZero(curve, &l_public));
    
    ecc_native2bytes(curve, p_privateKey, l_private);
    ecc_native2bytes(curve, p_publicKey + 1, l_public.x);
    p_publicKey[0] = 2 + (l_public.y[0] & 0x01);
    return 1;
}

/*int ecdh_shared_secret(const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_privateKey[ECC_BYTES], uint8_t p_secret[ECC_BYTES])
{
    EccPoint l_public;
    uint64_t l_private[NUM_ECC_DIGITS];
    uint64_t l_random[NUM_ECC_DIGITS];
    
    if(!getRandomNumber(l_random))
    {
        return 0;
    }
    
    ecc_point_decompress(&l_public, p_publicKey);
    ecc_bytes2native(l_private, p_privateKey);
    
    EccPoint l_product;
    EccPoint_mult(&l_product, &l_public, l_private, l_random);
    
    ecc_native2bytes(p_secret, l_product.x);
    
    return !EccPoint_isZero(&l_product);
}*/

/* -------- ECDSA code -------- */

/* Computes p_result = (p_left * p_right) % p_mod. */
static void vli_modMult(uint8_t curve, uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
    uint64_t l_product[2 * 9];
    uint64_t l_modMultiple[2 * 9];
    uint l_digitShift, l_bitShift;
    uint l_productBits;
    uint l_modBits = vli_numBits(curve, p_mod);
    
    vli_mult(curve, l_product, p_left, p_right);
    l_productBits = vli_numBits(curve, l_product + (curve>>3));
    if(l_productBits)
    {
        l_productBits += (curve>>3) * 64;
    }
    else
    {
        l_productBits = vli_numBits(curve, l_product);
    }
    
    if(l_productBits < l_modBits)
    { /* l_product < p_mod. */
        vli_set(curve, p_result, l_product);
        return;
    }
    
    /* Shift p_mod by (l_leftBits - l_modBits). This multiplies p_mod by the largest
       power of two possible while still resulting in a number less than p_left. */
    vli_clear(curve, l_modMultiple);
    vli_clear(curve, l_modMultiple + (curve>>3));
    l_digitShift = (l_productBits - l_modBits) / 64;
    l_bitShift = (l_productBits - l_modBits) % 64;
    if(l_bitShift)
    {
        l_modMultiple[l_digitShift + (curve>>3)] = vli_lshift(curve, l_modMultiple + l_digitShift, p_mod, l_bitShift);
    }
    else
    {
        vli_set(curve, l_modMultiple + l_digitShift, p_mod);
    }

    /* Subtract all multiples of p_mod to get the remainder. */
    vli_clear(curve, p_result);
    p_result[0] = 1; /* Use p_result as a temp var to store 1 (for subtraction) */
    while(l_productBits > (curve>>3) * 64 || vli_cmp(curve, l_modMultiple, p_mod) >= 0)
    {
        int l_cmp = vli_cmp(curve, l_modMultiple + (curve>>3), l_product + (curve>>3));
        if(l_cmp < 0 || (l_cmp == 0 && vli_cmp(curve, l_modMultiple, l_product) <= 0))
        {
            if(vli_sub(curve, l_product, l_product, l_modMultiple))
            { /* borrow */
                vli_sub(curve, l_product + (curve>>3), l_product + (curve>>3), p_result);
            }
            vli_sub(curve, l_product + (curve>>3), l_product + (curve>>3), l_modMultiple + (curve>>3));
        }
        uint64_t l_carry = (l_modMultiple[(curve>>3)] & 0x01) << 63;
        vli_rshift1(curve, l_modMultiple + (curve>>3));
        vli_rshift1(curve, l_modMultiple);
        l_modMultiple[(curve>>3)-1] |= l_carry;
        
        --l_productBits;
    }
    vli_set(curve, p_result, l_product);
}

static uint umax(uint a, uint b)
{
    return (a > b ? a : b);
}

int ecdsa_sign(uint8_t curve, const uint8_t * p_privateKey, const uint8_t * p_hash, uint8_t * p_signature,uint64_t * k)
{
    
    uint64_t l_tmp[9];
    uint64_t l_s[9];
    EccPoint p;

    EccPoint curve_g;
    uint64_t * curve_n;
    if(curve == secp256r1)
    {curve_g = Curve_G_32;curve_n = Curve_N_32;}
    else if (curve == secp384r1)
    { curve_g = Curve_G_48;curve_n = Curve_N_48;}
    else if (curve == secp521r1)
    { curve_g = Curve_G_72;curve_n = Curve_N_72;}
    else 
    { curve_g = Curve_G_32;curve_n = Curve_N_32;}

    //unsigned l_tries = 0;
    
    do
    {
        /*if(!getRandomNumber(k) || (l_tries++ >= MAX_TRIES))
        {
            return 0;
        }*/
        if(vli_isZero(curve, k))
        {
            continue;
        }
    
        if(vli_cmp(curve, curve_n, k) != 1)
        {
            vli_sub(curve, k, k, curve_n);
        }
    
        /* tmp = k * G */
        EccPoint_mult(curve, &p, &curve_g, k, NULL);
    
        /* r = x1 (mod n) */
        if(vli_cmp(curve, curve_n, p.x) != 1)
        {
            vli_sub(curve, p.x, p.x, curve_n);
        }
    } while(vli_isZero(curve, p.x));

    ecc_native2bytes(curve, p_signature, p.x);
    
    ecc_bytes2native(curve, l_tmp, p_privateKey);
    vli_modMult(curve, l_s, p.x, l_tmp, curve_n); /* s = r*d */
    ecc_bytes2native(curve, l_tmp, p_hash);
    vli_modAdd(curve, l_s, l_tmp, l_s, curve_n); /* s = e + r*d */
    #ifdef DEBUG
    /*int count=0;
    for (int i=0; i<4;i++){
       for (int j=0; j<8;j++){
         count++;
         uart_put_hex_1b((void*)uart, l_s[j+8*i]);
         if(count == 16){
           uart_puts((void *)uart_reg, "\n");
           count = 0;
        }
       }
  }*/
    #endif
    vli_modInv(curve, k, k, curve_n); /* k = 1 / k */
    vli_modMult(curve, l_s, l_s, k, curve_n); /* s = (e + r*d) / k */
    #ifdef DEBUG
    /*count=0;
    for (int i=0; i<4;i++){
       for (int j=0; j<8;j++){
         count++;
         uart_put_hex_1b((void*)uart, l_s[j+8*i]);
         if(count == 16){
           uart_puts((void *)uart_reg, "\n");
           count = 0;
        }
       }
  }*/
    #endif
    ecc_native2bytes(curve, p_signature + (curve), l_s);
    
    return 1;
}

int ecdsa_verify(uint8_t curve, const uint8_t * p_publicKey, const uint8_t * p_hash, const uint8_t * p_signature)
{
    uint64_t u1[9], u2[9];
    uint64_t z[9];
    EccPoint l_public, l_sum;
    uint64_t rx[9];
    uint64_t ry[9];
    uint64_t tx[9];
    uint64_t ty[9];
    uint64_t tz[9];
    
    uint64_t l_r[9], l_s[9];
    
    uint64_t * curve_p;
    uint64_t * curve_n;
    EccPoint curve_g;
    if(curve == secp256r1)
    { curve_p = Curve_P_32; curve_n = Curve_N_32; curve_g = Curve_G_32;}
    else if (curve == secp384r1)
    { curve_p = Curve_P_48; curve_n = Curve_N_48; curve_g = Curve_G_48;}
    else if (curve == secp521r1)
    { curve_p = Curve_P_72; curve_n = Curve_N_72; curve_g = Curve_G_72;}
    else 
    { curve_p = Curve_P_32; curve_n = Curve_N_32; curve_g = Curve_G_32;}

    ecc_point_decompress(curve, &l_public, p_publicKey);
    ecc_bytes2native(curve, l_r, p_signature);
    ecc_bytes2native(curve, l_s, p_signature + curve);
    
    if(vli_isZero(curve, l_r) || vli_isZero(curve, l_s))
    { /* r, s must not be 0. */
        return 0;
    }
    
    if(vli_cmp(curve, curve_n, l_r) != 1 || vli_cmp(curve, curve_n, l_s) != 1)
    { /* r, s must be < n. */
        return 0;
    }

    /* Calculate u1 and u2. */

    vli_modInv(curve, z, l_s, curve_n); /* Z = s^-1 */
    ecc_bytes2native(curve, u1, p_hash);
    vli_modMult(curve, u1, u1, z, curve_n); /* u1 = e/s */
    vli_modMult(curve, u2, l_r, z, curve_n); /* u2 = r/s */
    
    /* Calculate l_sum = G + Q. */
    vli_set(curve, l_sum.x, l_public.x);
    vli_set(curve, l_sum.y, l_public.y);
    vli_set(curve, tx, curve_g.x);
    vli_set(curve, ty, curve_g.y);
    vli_modSub(curve, z, l_sum.x, tx, curve_p); /* Z = x2 - x1 */
    XYcZ_add(curve, tx, ty, l_sum.x, l_sum.y);
    vli_modInv(curve, z, z, curve_p); /* Z = 1/Z */
    apply_z(curve, l_sum.x, l_sum.y, z);
    
    /* Use Shamir's trick to calculate u1*G + u2*Q */
    EccPoint *l_points[4] = {NULL, &curve_g, &l_public, &l_sum};
    uint l_numBits = umax(vli_numBits(curve, u1), vli_numBits(curve, u2));
    
    EccPoint *l_point = l_points[(!!vli_testBit(u1, l_numBits-1)) | ((!!vli_testBit(u2, l_numBits-1)) << 1)];
    vli_set(curve, rx, l_point->x);
    vli_set(curve, ry, l_point->y);
    vli_clear(curve, z);
    z[0] = 1;

    int i;
    for(i = l_numBits - 2; i >= 0; --i)
    {
        EccPoint_double_jacobian(curve, rx, ry, z);
        
        int l_index = (!!vli_testBit(u1, i)) | ((!!vli_testBit(u2, i)) << 1);
        EccPoint *l_point = l_points[l_index];
        if(l_point)
        {
            vli_set(curve, tx, l_point->x);
            vli_set(curve, ty, l_point->y);
            apply_z(curve, tx, ty, z);
            vli_modSub(curve, tz, rx, tx, curve_p); /* Z = x2 - x1 */
            XYcZ_add(curve, tx, ty, rx, ry);
            vli_modMult_fast(curve, z, z, tz);
        }
    }

    vli_modInv(curve, z, z, curve_p); /* Z = 1/Z */
    apply_z(curve, rx, ry, z);
    
    /* v = x1 (mod n) */
    if(vli_cmp(curve, curve_n, rx) != 1)
    {
        vli_sub(curve, rx, rx, curve_n);
    }

    /* Accept only if v == r. */
    return (vli_cmp(curve, rx, l_r) == 0);
}
