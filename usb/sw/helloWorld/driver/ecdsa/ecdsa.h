#ifndef _EASY_ECC_H_
#define _EASY_ECC_H_

#include <stdint.h>
#include "driver/uart/uart.h"
#include <string.h>

/* Curve selection options. */
#define secp256r1 32
#define secp384r1 48
#define secp521r1 72 //66
#ifndef ECC_CURVE
    #define ECC_CURVE secp256r1
#endif

#if (ECC_CURVE != secp128r1 && ECC_CURVE != secp192r1 && ECC_CURVE != secp256r1 && ECC_CURVE != secp384r1 && ECC_CURVE != secp521r1)
    #error "Must define ECC_CURVE to one of the available curves"
#endif

#define ECC_BYTES ECC_CURVE
#define NUM_ECC_DIGITS (ECC_BYTES/8)

#ifdef __cplusplus
extern "C"
{
#endif

/* ecc_make_key() function.
Create a public/private key pair.

Inputs:
    l_private  - The public key of the remote party.

Outputs:
    p_publicKey  - A random number.
    p_privateKey - Will be filled in with the private key.

Returns 1 if the key pair was generated successfully, 0 if an error occurred.
*/
int ecc_make_key(uint8_t curve, uint8_t * p_publicKey, uint8_t * p_privateKey,  uint64_t * l_private);

/* ecdh_shared_secret() function.
Compute a shared secret given your secret key and someone else's public key.
Note: It is recommended that you hash the result of ecdh_shared_secret before using it for symmetric encryption or HMAC.

Inputs:
    p_publicKey  - The public key of the remote party.
    p_privateKey - Your private key.
    l_random     - A random number.

Outputs:
    p_secret - Will be filled in with the shared secret value.

Returns 1 if the shared secret was generated successfully, 0 if an error occurred.
*/
int ecdh_shared_secret(uint8_t curve, const uint8_t * p_publicKey, const uint8_t * p_privateKey, uint8_t * p_secret,uint64_t * l_random);

/* ecdsa_sign() function.
Generate an ECDSA signature for a given hash value.

Usage: Compute a hash of the data you wish to sign (SHA-2 is recommended) and pass it in to
this function along with your private key.

Inputs:
    p_privateKey - Your private key.
    p_hash       - The message hash to sign.
    k            - A random number.

Outputs:
    p_signature  - Will be filled in with the signature value.

Returns 1 if the signature generated successfully, 0 if an error occurred.
*/
int ecdsa_sign(uint8_t curve, const uint8_t * p_privateKey, const uint8_t * p_hash, uint8_t * p_signature,uint64_t * k);

/* ecdsa_verify() function.
Verify an ECDSA signature.

Usage: Compute the hash of the signed data using the same hash as the signer and
pass it to this function along with the signer's public key and the signature values (r and s).

Inputs:
    p_publicKey - The signer's public key
    p_hash      - The hash of the signed data.
    p_signature - The signature value.

Returns 1 if the signature is valid, 0 if it is invalid.
*/
int ecdsa_verify(uint8_t curve, const uint8_t * p_publicKey, const uint8_t * p_hash, const uint8_t * p_signature);

void ecc_native2bytes(uint8_t curve, uint8_t * p_bytes, const uint64_t * p_native);
#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* _EASY_ECC_H_ */
