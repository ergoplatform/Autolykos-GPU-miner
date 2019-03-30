// cryptography.cu

/*******************************************************************************

    CRYPTOGRAPHY -- Key-pair handling with Openssl

*******************************************************************************/

#include "../include/cryptography.h"
#include "../include/conversion.h"
#include "../include/definitions.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

////////////////////////////////////////////////////////////////////////////////
//  Generate key pair
////////////////////////////////////////////////////////////////////////////////
int GenerateKeyPair(
    uint8_t * sk,
    uint8_t * pk
)
{
    EC_KEY * eck = NULL;
    EVP_PKEY * evpk = NULL;

    FUNCTION_CALL(eck, EC_KEY_new_by_curve_name(NID_secp256k1), ERROR_OPENSSL);

    // OPENSSL_EC_NAMED_CURVE flag for cert signing
    EC_KEY_set_asn1_flag(eck, OPENSSL_EC_NAMED_CURVE);

    // create public/private EC key pair
    CALL(EC_KEY_generate_key(eck), ERROR_OPENSSL);

    // convert EC key into PKEY structure
    evpk = EVP_PKEY_new();
    CALL(EVP_PKEY_assign_EC_KEY(evpk, eck), ERROR_OPENSSL);

    // extract EC-specifics from the key
    FUNCTION_CALL(eck, EVP_PKEY_get1_EC_KEY(evpk), ERROR_OPENSSL);

    //====================================================================//
    //  Public key extraction
    //====================================================================//
    const EC_GROUP * group = EC_KEY_get0_group(eck);
    const EC_POINT * ecp = EC_KEY_get0_public_key(eck);

    CALL(group, ERROR_OPENSSL);
    CALL(ecp, ERROR_OPENSSL);

    char * str;
    
    FUNCTION_CALL(
        str, EC_POINT_point2hex(group, ecp, POINT_CONVERSION_COMPRESSED, NULL),
        ERROR_OPENSSL
    );

    int len = 0;

    for ( ; str[len] != '\0'; ++len) {}

    HexStrToBigEndian(str, len, pk, PK_SIZE_8);

    OPENSSL_free(str);
    str = NULL;

    //====================================================================//
    //  Secret key extraction
    //====================================================================//
    const BIGNUM * bn = EC_KEY_get0_private_key(eck);
    CALL(bn, ERROR_OPENSSL);

    FUNCTION_CALL(str, BN_bn2hex(bn), ERROR_OPENSSL);
    len = 0;

    for ( ; str[len] != '\0'; ++len) {}

    HexStrToLittleEndian(str, len, sk, NUM_SIZE_8);

    OPENSSL_free(str);

    //====================================================================//
    //  Deallocation
    //====================================================================//
    EVP_PKEY_free(evpk);
    EC_KEY_free(eck);

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Generate public key from private
////////////////////////////////////////////////////////////////////////////////
int GeneratePublicKey(
    const char * skstr,
    char * pkstr,
    uint8_t * pk
)
{
    EC_KEY * eck = NULL;
    EC_POINT * sec = NULL;
    BIGNUM start;
    BIGNUM * res;
    BN_CTX * ctx;

    BN_init(&start);

    FUNCTION_CALL(ctx, BN_CTX_new(), ERROR_OPENSSL);

    res = &start;
    CALL(BN_hex2bn(&res, skstr), ERROR_OPENSSL);

    FUNCTION_CALL(eck, EC_KEY_new_by_curve_name(NID_secp256k1), ERROR_OPENSSL);

    const EC_GROUP * group = EC_KEY_get0_group(eck);
    CALL(group, ERROR_OPENSSL);

    FUNCTION_CALL(sec, EC_POINT_new(group), ERROR_OPENSSL);

    CALL(EC_KEY_set_private_key(eck, res), ERROR_OPENSSL);

    CALL(EC_POINT_mul(group, sec, res, NULL, NULL, ctx), ERROR_OPENSSL);
    CALL(EC_KEY_set_public_key(eck, sec), ERROR_OPENSSL);

    //====================================================================//
    //  Public key extraction
    //====================================================================//
    const EC_POINT * pub = EC_KEY_get0_public_key(eck);

    CALL(pub, ERROR_OPENSSL);

    char * str;

    FUNCTION_CALL(
        str, EC_POINT_point2hex(group, pub, POINT_CONVERSION_COMPRESSED, NULL),
        ERROR_OPENSSL
    );

    strcpy(pkstr, str);

    int len = 0;

    for ( ; str[len] != '\0'; ++len) {}

    HexStrToBigEndian(str, len, pk, PK_SIZE_8);

    //====================================================================//
    //  Deallocation
    //====================================================================//
    OPENSSL_free(str);
    BN_CTX_free(ctx);
    EC_KEY_free(eck);

    return EXIT_SUCCESS;
}

// cryptography.cu
