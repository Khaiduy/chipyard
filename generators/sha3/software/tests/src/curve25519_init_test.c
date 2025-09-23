/* test_curve25519.c
 * Replica of WolfSSL Curve25519 API tests without ExpectIntEQ
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "compiler.h"
#include <wolfssl/options.h>


#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
// Static memory setup for WolfSSL
#define WOLFSSL_STATIC_MEM_SIZE 32768
static byte g_wolfssl_mem[WOLFSSL_STATIC_MEM_SIZE];
static WOLFSSL_HEAP_HINT* g_heap_hint = NULL;

// Test result tracking
static int test_failures = 0;

// Replace ExpectIntEQ with direct checking
#define ExpectIntEQ(actual, expected) do { \
    int _actual = (actual); \
    int _expected = (expected); \
    if (_actual != _expected) { \
        printf("FAIL: Expected %d, got %d at line %d\n", _expected, _actual, __LINE__); \
        test_failures++; \
        goto exit_test; \
    } else { \
        printf("PASS: %s == %d\n", #actual, _expected); \
    } \
} while(0)

// Setup static memory (added for our fix)
static int setup_wolfssl_memory(void)
{
#ifdef WOLFSSL_STATIC_MEMORY
    int ret = wc_LoadStaticMemory(&g_heap_hint, g_wolfssl_mem, 
                                  WOLFSSL_STATIC_MEM_SIZE, 0, 20);
    if (ret != 0) {
        printf("wc_LoadStaticMemory failed: %d\n", ret);
        return ret;
    }
    printf("Static memory initialized successfully\n");
    return 0;
#else
    printf("WOLFSSL_STATIC_MEMORY not defined\n");
    return -1;
#endif
}

/*
 * Testing wc_curve25519_init and wc_curve25519_free
 */
static int test_wc_curve25519_init(void)
{
    int ret = 0;
#if defined(HAVE_CURVE25519)
    curve25519_key key;

    ret = wc_curve25519_init(&key);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    /* Test bad args for wc_curve25519_init */
    ret = wc_curve25519_init(NULL);
    if (ret == BAD_FUNC_ARG) {
        printf("PASS: ret == %d\n", ret);
        ret = 0; // Reset to success
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", BAD_FUNC_ARG, ret, __LINE__);
        ret = -1;
        goto exit_test;
    }

    /* Test good args for wc_curve25519_free */
    wc_curve25519_free(&key);

    /* Test bad args for wc_curve25519_free */
    wc_curve25519_free(NULL);

exit_test:
    return ret;

#else
    return 0;
#endif
} /* END test_wc_curve25519_init */

/*
 * Testing wc_curve25519_size
 */
static int test_wc_curve25519_size(void)
{
    int ret = 0;
#if defined(HAVE_CURVE25519)
    curve25519_key key;

    ret = wc_curve25519_init(&key);
    ExpectIntEQ(ret, 0);

    /* Test good args for wc_curve25519_size */
    ret = wc_curve25519_size(&key);
    ExpectIntEQ(ret, CURVE25519_KEYSIZE);

    /* Test bad args for wc_curve25519_size */
    ret = wc_curve25519_size(NULL);
    ExpectIntEQ(ret, 0);

exit_test:
    wc_curve25519_free(&key);
    return ret;

#else
    return 0;
#endif
} /* END test_wc_curve25519_size */

/*
 * Testing wc_curve25519_make_key
 */
static int test_wc_curve25519_make_key(void)
{
    int ret = 0;
#if defined(HAVE_CURVE25519)
    curve25519_key key;
    WC_RNG rng;
    int keysize;

    ret = wc_curve25519_init(&key);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    // Initialize RNG with static memory (OUR FIX)
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    /* Test good args for wc_curve25519_make_key */
    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    /* Test good args for wc_curve25519_make_key */
    keysize = wc_curve25519_size(&key);
    if (keysize == CURVE25519_KEYSIZE) {
        printf("PASS: keysize == %d\n", keysize);
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", CURVE25519_KEYSIZE, keysize, __LINE__);
        ret = -1;
        goto exit_test;
    }
    ret = wc_curve25519_make_key(&rng, keysize, &key);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    /* Test bad args for wc_curve25519_make_key */
    ret = wc_curve25519_make_key(NULL, 0, NULL);
    if (ret == BAD_FUNC_ARG) {
        printf("PASS: ret == %d\n", ret);
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", BAD_FUNC_ARG, ret, __LINE__);
        ret = -1;
        goto exit_test;
    }

    ret = wc_curve25519_make_key(&rng, keysize, NULL);
    if (ret == BAD_FUNC_ARG) {
        printf("PASS: ret == %d\n", ret);
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", BAD_FUNC_ARG, ret, __LINE__);
        ret = -1;
        goto exit_test;
    }

    ret = wc_curve25519_make_key(NULL, keysize, &key);
    if (ret == BAD_FUNC_ARG) {
        printf("PASS: ret == %d\n", ret);
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", BAD_FUNC_ARG, ret, __LINE__);
        ret = -1;
        goto exit_test;
    }

    ret = wc_curve25519_make_key(&rng, 0, &key);
    if (ret == ECC_BAD_ARG_E) {
        printf("PASS: ret == %d\n", ret);
        ret = 0; // Reset to success
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", ECC_BAD_ARG_E, ret, __LINE__);
        ret = -1;
    }

exit_test:
    wc_FreeRng(&rng);
    wc_curve25519_free(&key);

    return ret;
#else
    return 0;
#endif
} /* END test_wc_curve25519_make_key */

/*
 * Testing wc_curve25519_shared_secret_ex
 */
static int test_wc_curve25519_shared_secret_ex(void)
{
    int ret = 0;
#if defined(HAVE_CURVE25519)
    curve25519_key private_key;
    curve25519_key public_key;
    WC_RNG rng;
    byte out[CURVE25519_KEYSIZE];
    word32 outLen = sizeof(out);
    int endian = EC25519_BIG_ENDIAN;

    ret = wc_curve25519_init(&private_key);
    ExpectIntEQ(ret, 0);

    ret = wc_curve25519_init(&public_key);
    ExpectIntEQ(ret, 0);

    // Initialize RNG with static memory (OUR FIX)
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    ExpectIntEQ(ret, 0);

#ifdef WOLFSSL_CURVE25519_BLINDING
    ret = wc_curve25519_set_rng(&private_key, &rng);
    ExpectIntEQ(ret, 0);
#endif

    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &private_key);
    ExpectIntEQ(ret, 0);

    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &public_key);
    ExpectIntEQ(ret, 0);

    ret = wc_curve25519_shared_secret_ex(&private_key, &public_key, out,
                                         &outLen, endian);
    ExpectIntEQ(ret, 0);

    /* Test bad args for wc_curve25519_shared_secret_ex */
    ret = wc_curve25519_shared_secret_ex(NULL, NULL, NULL, 0, endian);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_shared_secret_ex(NULL, &public_key, out, &outLen,
                                         endian);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_shared_secret_ex(&private_key, NULL, out, &outLen,
                                         endian);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_shared_secret_ex(&private_key, &public_key, NULL,
                                         &outLen, endian);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_shared_secret_ex(&private_key, &public_key, out,
                                         NULL, endian);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    /* reset for test */
    outLen = sizeof(out);
    ret = wc_curve25519_shared_secret_ex(&private_key, &public_key, out,
                                         &outLen, endian);
    ExpectIntEQ(ret, 0);

exit_test:
    wc_FreeRng(&rng);
    wc_curve25519_free(&private_key);
    wc_curve25519_free(&public_key);

    return ret;
#else
    return 0;
#endif
} /* END test_wc_curve25519_shared_secret_ex */

/*
 * Testing wc_curve25519_export_key_raw
 */
static int test_wc_curve25519_export_key_raw(void)
{
    int ret = 0;
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_EXPORT)
    curve25519_key key;
    WC_RNG rng;
    byte privateKey[CURVE25519_KEYSIZE];
    byte publicKey[CURVE25519_KEYSIZE];
    word32 prvkSz = CURVE25519_KEYSIZE;
    word32 pubkSz = CURVE25519_KEYSIZE;
    byte prik[CURVE25519_KEYSIZE];
    byte pubk[CURVE25519_KEYSIZE];
    word32 prksz = CURVE25519_KEYSIZE;
    word32 pbksz = CURVE25519_KEYSIZE;

    ret = wc_curve25519_init(&key);
    ExpectIntEQ(ret, 0);

    // Initialize RNG with static memory (OUR FIX)
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    ExpectIntEQ(ret, 0);

    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key);
    ExpectIntEQ(ret, 0);

    /*export key raw*/
    ret = wc_curve25519_export_key_raw(&key, privateKey, &prvkSz, publicKey,
                                       &pubkSz);
    ExpectIntEQ(ret, 0);

    /* Test bad args for wc_curve25519_export_key_raw */
    ret = wc_curve25519_export_key_raw(NULL, privateKey, &prvkSz, publicKey,
                                       &pubkSz);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_export_key_raw(&key, NULL, &prvkSz, publicKey,
                                       &pubkSz);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_export_key_raw(&key, privateKey, NULL, publicKey,
                                       &pubkSz);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_export_key_raw(&key, privateKey, &prvkSz, NULL,
                                       &pubkSz);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_export_key_raw(&key, privateKey, &prvkSz, publicKey,
                                       NULL);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    /* cross-testing */
    ret = wc_curve25519_export_private_raw(&key, prik, &prksz);
    ExpectIntEQ(ret, 0);

    ret = wc_curve25519_export_public(&key, pubk, &pbksz);
    ExpectIntEQ(ret, 0);

    prvkSz = CURVE25519_KEYSIZE;
    pubkSz = CURVE25519_KEYSIZE;

    ret = wc_curve25519_export_key_raw(&key, privateKey, &prvkSz, publicKey,
                                       &pubkSz);
    ExpectIntEQ(ret, 0);

    ExpectIntEQ(prksz, CURVE25519_KEYSIZE);
    ExpectIntEQ(pbksz, CURVE25519_KEYSIZE);
    ExpectIntEQ(prvkSz, CURVE25519_KEYSIZE);
    ExpectIntEQ(pubkSz, CURVE25519_KEYSIZE);

    ExpectIntEQ(XMEMCMP(privateKey, prik, CURVE25519_KEYSIZE), 0);
    ExpectIntEQ(XMEMCMP(publicKey, pubk, CURVE25519_KEYSIZE), 0);

exit_test:
    wc_FreeRng(&rng);
    wc_curve25519_free(&key);

    return ret;
#else
    return 0;
#endif
} /* END test_wc_curve25519_export_key_raw */

/*
 * Testing wc_curve25519_import_private_raw and wc_curve25519_export_private_raw
 */
static int test_wc_curve25519_import_private_raw(void)
{
    int ret = 0;
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
    curve25519_key key;
    WC_RNG rng;
    byte privateKey[CURVE25519_KEYSIZE];
    byte publicKey[CURVE25519_KEYSIZE];
    word32 prvkSz = CURVE25519_KEYSIZE;
    word32 pubkSz = CURVE25519_KEYSIZE;

    ret = wc_curve25519_init(&key);
    ExpectIntEQ(ret, 0);

    // Initialize RNG with static memory (OUR FIX)
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    ExpectIntEQ(ret, 0);

    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key);
    ExpectIntEQ(ret, 0);

    ret = wc_curve25519_export_private_raw(&key, privateKey, &prvkSz);
    ExpectIntEQ(ret, 0);

    ret = wc_curve25519_export_public(&key, publicKey, &pubkSz);
    ExpectIntEQ(ret, 0);

    /* Test good args for wc_curve25519_import_private_raw */
    ret = wc_curve25519_import_private_raw(privateKey, CURVE25519_KEYSIZE,
                                           publicKey, CURVE25519_KEYSIZE, &key);
    ExpectIntEQ(ret, 0);

    /* Test bad args for wc_curve25519_import_private_raw */
    ret = wc_curve25519_import_private_raw(NULL, 0, NULL, 0, NULL);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_import_private_raw(NULL, CURVE25519_KEYSIZE, publicKey,
                                           CURVE25519_KEYSIZE, &key);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_import_private_raw(privateKey, CURVE25519_KEYSIZE,
                                           NULL, CURVE25519_KEYSIZE, &key);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_import_private_raw(privateKey, CURVE25519_KEYSIZE,
                                           publicKey, CURVE25519_KEYSIZE, NULL);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_import_private_raw(privateKey, 0, publicKey,
                                           CURVE25519_KEYSIZE, &key);
    ExpectIntEQ(ret, ECC_BAD_ARG_E);

    ret = wc_curve25519_import_private_raw(privateKey, CURVE25519_KEYSIZE,
                                           publicKey, 0, &key);
    ExpectIntEQ(ret, ECC_BAD_ARG_E);

    ret = wc_curve25519_import_private_raw(privateKey, CURVE25519_KEYSIZE,
                                           publicKey, CURVE25519_KEYSIZE, &key);
    ExpectIntEQ(ret, 0);

exit_test:
    wc_FreeRng(&rng);
    wc_curve25519_free(&key);

    return ret;
#else
    return 0;
#endif
} /* END test_wc_curve25519_import_private_raw */

/*
 * Testing wc_curve25519_import_public and wc_curve25519_export_public_ex
 */
static int test_wc_curve25519_import_public(void)
{
    int ret = 0;
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
    curve25519_key key;
    WC_RNG rng;
    byte publicKey[CURVE25519_KEYSIZE];
    word32 pubkSz = CURVE25519_KEYSIZE;
    int endian = EC25519_BIG_ENDIAN;

    ret = wc_curve25519_init(&key);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    // Initialize RNG with static memory (OUR FIX)
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    ret = wc_curve25519_export_public_ex(&key, publicKey, &pubkSz, endian);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    /* Test good args for wc_curve25519_import_public */
    ret = wc_curve25519_import_public_ex(publicKey, CURVE25519_KEYSIZE, &key,
                                         endian);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    /* Test bad args for wc_curve25519_import_public */
    ret = wc_curve25519_import_public_ex(NULL, 0, NULL, 0);
    if (ret == BAD_FUNC_ARG) {
        printf("PASS: ret == %d\n", ret);
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", BAD_FUNC_ARG, ret, __LINE__);
        ret = -1;
        goto exit_test;
    }

    ret = wc_curve25519_import_public_ex(NULL, CURVE25519_KEYSIZE, &key,
                                         endian);
    if (ret == BAD_FUNC_ARG) {
        printf("PASS: ret == %d\n", ret);
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", BAD_FUNC_ARG, ret, __LINE__);
        ret = -1;
        goto exit_test;
    }

    ret = wc_curve25519_import_public_ex(publicKey, CURVE25519_KEYSIZE, NULL,
                                         endian);
    if (ret == BAD_FUNC_ARG) {
        printf("PASS: ret == %d\n", ret);
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", BAD_FUNC_ARG, ret, __LINE__);
        ret = -1;
        goto exit_test;
    }

    ret = wc_curve25519_import_public_ex(publicKey, 0, &key, endian);
    if (ret == ECC_BAD_ARG_E) {
        printf("PASS: ret == %d\n", ret);
        ret = 0; // Reset to success
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", ECC_BAD_ARG_E, ret, __LINE__);
        ret = -1;
    }

exit_test:
    wc_FreeRng(&rng);
    wc_curve25519_free(&key);

    return ret;
#else
    return 0;
#endif
} /* END test_wc_curve25519_import_public */

/*
 * Testing wc_curve25519_check_public
 */
static int test_wc_curve25519_check_public(void)
{
    int ret = 0;
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
    curve25519_key key;
    WC_RNG rng;
    byte publicKey[CURVE25519_KEYSIZE];
    word32 pubkSz = CURVE25519_KEYSIZE;
    int endian = EC25519_BIG_ENDIAN;

    ret = wc_curve25519_init(&key);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    // Initialize RNG with static memory (OUR FIX)
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    ret = wc_curve25519_export_public_ex(&key, publicKey, &pubkSz, endian);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    ret = wc_curve25519_import_public_ex(publicKey, CURVE25519_KEYSIZE, &key,
                                         endian);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    ret = wc_curve25519_check_public(publicKey, CURVE25519_KEYSIZE, endian);
    if (ret == 0) {
        printf("PASS: ret == 0\n");
    } else {
        printf("FAIL: Expected 0, got %d at line %d\n", ret, __LINE__);
        goto exit_test;
    }

    /* Test bad args for wc_curve25519_check_public */
    ret = wc_curve25519_check_public(NULL, 0, endian);
    if (ret == BAD_FUNC_ARG) {
        printf("PASS: ret == %d\n", ret);
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", BAD_FUNC_ARG, ret, __LINE__);
        ret = -1;
        goto exit_test;
    }

    ret = wc_curve25519_check_public(publicKey, 0, endian);
    if (ret == ECC_BAD_ARG_E) {
        printf("PASS: ret == %d\n", ret);
        ret = 0; // Reset to success
    } else {
        printf("FAIL: Expected %d, got %d at line %d\n", ECC_BAD_ARG_E, ret, __LINE__);
        ret = -1;
    }

exit_test:
    wc_FreeRng(&rng);
    wc_curve25519_free(&key);

    return ret;
#else
    return 0;
#endif
} /* END test_wc_curve25519_check_public */

/*
 * Testing wc_curve25519_size and wc_curve25519_shared_secret
 */
static int test_wc_curve25519_shared_secret(void)
{
    int ret = 0;
#if defined(HAVE_CURVE25519)
    curve25519_key private_key;
    curve25519_key public_key;
    WC_RNG rng;
    byte out[CURVE25519_KEYSIZE];
    word32 outLen = sizeof(out);

    /* init keys */
    ret = wc_curve25519_init(&private_key);
    ExpectIntEQ(ret, 0);
    ret = wc_curve25519_init(&public_key);
    ExpectIntEQ(ret, 0);

    /* init rng */
    // Initialize RNG with static memory (OUR FIX)
    ret = wc_InitRng_ex(&rng, g_heap_hint, INVALID_DEVID);
    ExpectIntEQ(ret, 0);

    /* Make keys */
    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &private_key);
    ExpectIntEQ(ret, 0);
    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &public_key);
    ExpectIntEQ(ret, 0);

    /* Make shared secret */
    ret = wc_curve25519_shared_secret(&private_key, &public_key, out, &outLen);
    ExpectIntEQ(ret, 0);

    /* Test bad args for wc_curve25519_shared_secret */
    ret = wc_curve25519_shared_secret(NULL, NULL, NULL, 0);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_shared_secret(NULL, &public_key, out, &outLen);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_shared_secret(&private_key, NULL, out, &outLen);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_shared_secret(&private_key, &public_key, NULL, &outLen);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    ret = wc_curve25519_shared_secret(&private_key, &public_key, out, NULL);
    ExpectIntEQ(ret, BAD_FUNC_ARG);

    /* reset for next test */
    outLen = sizeof(out);
    ret = wc_curve25519_shared_secret(&private_key, &public_key, out, &outLen);
    ExpectIntEQ(ret, 0);

exit_test:
    wc_FreeRng(&rng);
    wc_curve25519_free(&private_key);
    wc_curve25519_free(&public_key);

    return ret;
#else
    return 0;
#endif
} /* END test_wc_curve25519_shared_secret */

/* Main test function that calls all the individual tests */
int main(void)
{
    int result = 0;
    
    printf("WolfSSL Curve25519 API Test Suite\n");
    printf("=================================\n");
    
    unsigned long start = rdcycle();
    
    // Setup static memory (OUR ADDITION)
    printf("Setting up static memory...\n");
    if (setup_wolfssl_memory() != 0) {
        printf("Static memory setup failed!\n");
        return -1;
    }
    
    printf("Running Curve25519 tests...\n\n");

    printf("Testing wc_curve25519_init...\n");
    if (test_wc_curve25519_init() != 0) {
        printf("test_wc_curve25519_init FAILED\n");
        result = -1;
    } else {
        printf("test_wc_curve25519_init PASSED\n");
    }
    printf("\n");

    printf("Testing wc_curve25519_size...\n");
    if (test_wc_curve25519_size() != 0) {
        printf("test_wc_curve25519_size FAILED\n");
        result = -1;
    } else {
        printf("test_wc_curve25519_size PASSED\n");
    }
    printf("\n");

    printf("Testing wc_curve25519_make_key...\n");
    if (test_wc_curve25519_make_key() != 0) {
        printf("test_wc_curve25519_make_key FAILED\n");
        result = -1;
    } else {
        printf("test_wc_curve25519_make_key PASSED\n");
    }
    printf("\n");

    printf("Testing wc_curve25519_shared_secret_ex...\n");
    if (test_wc_curve25519_shared_secret_ex() != 0) {
        printf("test_wc_curve25519_shared_secret_ex FAILED\n");
        result = -1;
    } else {
        printf("test_wc_curve25519_shared_secret_ex PASSED\n");
    }
    printf("\n");

    printf("Testing wc_curve25519_export_key_raw...\n");
    if (test_wc_curve25519_export_key_raw() != 0) {
        printf("test_wc_curve25519_export_key_raw FAILED\n");
        result = -1;
    } else {
        printf("test_wc_curve25519_export_key_raw PASSED\n");
    }
    printf("\n");

    printf("Testing wc_curve25519_import_private_raw...\n");
    if (test_wc_curve25519_import_private_raw() != 0) {
        printf("test_wc_curve25519_import_private_raw FAILED\n");
        result = -1;
    } else {
        printf("test_wc_curve25519_import_private_raw PASSED\n");
    }
    printf("\n");

    printf("Testing wc_curve25519_import_public...\n");
    if (test_wc_curve25519_import_public() != 0) {
        printf("test_wc_curve25519_import_public FAILED\n");
        result = -1;
    } else {
        printf("test_wc_curve25519_import_public PASSED\n");
    }
    printf("\n");

    printf("Testing wc_curve25519_check_public...\n");
    if (test_wc_curve25519_check_public() != 0) {
        printf("test_wc_curve25519_check_public FAILED\n");
        result = -1;
    } else {
        printf("test_wc_curve25519_check_public PASSED\n");
    }
    printf("\n");

    printf("Testing wc_curve25519_shared_secret...\n");
    if (test_wc_curve25519_shared_secret() != 0) {
        printf("test_wc_curve25519_shared_secret FAILED\n");
        result = -1;
    } else {
        printf("test_wc_curve25519_shared_secret PASSED\n");
    }
    printf("\n");

    unsigned long end = rdcycle();
    
    printf("=================================\n");
    printf("Test failures: %d\n", test_failures);
    printf("Total cycles: %lu\n", end - start);
    
    if (result == 0 && test_failures == 0) {
        printf("ALL TESTS PASSED!\n");
        printf("Static memory + wc_InitRng_ex solution works perfectly!\n");
    } else {
        printf("SOME TESTS FAILED\n");
        printf("Check individual test results above\n");
    }

    return result;
}