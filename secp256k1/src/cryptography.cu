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
#include <openssl/bio.h>
#include <openssl/err.h>
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
    BIO * outbio = NULL;
    EC_KEY * eck = NULL;
    EVP_PKEY * evpk = NULL;
    ///int eccgrp;

    // initialize openssl
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // create Input/Output BIO's
    outbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    // create EC key sructure
    // set group type from NID
    ///eccgrp = OBJ_txt2nid("secp256k1");
    ///eck = EC_KEY_new_by_curve_name(eccgrp);
    eck = EC_KEY_new_by_curve_name(NID_secp256k1);

    // OPENSSL_EC_NAMED_CURVE flag for cert signing
    EC_KEY_set_asn1_flag(eck, OPENSSL_EC_NAMED_CURVE);

    // create public/private EC key pair
    if (!(EC_KEY_generate_key(eck)))
    {
        BIO_printf(outbio, "Error generating the ECC key.");
    }

    // convert EC key into PKEY structure
    evpk = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(evpk, eck))
    {
        BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");
    }

    // Now we show how to extract EC-specifics from the key
    eck = EVP_PKEY_get1_EC_KEY(evpk);

    const EC_GROUP * ecgrp = EC_KEY_get0_group(eck);

    //====================================================================//
    //  Public key extraction
    //====================================================================//
    const EC_POINT * ecp = EC_KEY_get0_public_key(eck);

    char * str = EC_POINT_point2hex(
        ecgrp, ecp, POINT_CONVERSION_COMPRESSED, NULL
    );

    int len = 0;

    if (str)
    {
        for ( ; str[len] != '\0'; ++len) {}
    }
    else
    {
        printf("ERROR\n");
        fflush(stdout);
    }

    HexStrToBigEndian(str, len, pk, PK_SIZE_8);

    OPENSSL_free(str);
    str = NULL;

    //====================================================================//
    //  Secret key extraction
    //====================================================================//
    const BIGNUM * bn = EC_KEY_get0_private_key(eck);

    str = BN_bn2hex(bn);
    len = 0;

    if (str)
    {
        for ( ; str[len] != '\0'; ++len) {}
    }
    else
    {
        printf("ERROR\n");
        fflush(stdout);
    }

    HexStrToLittleEndian(str, len, sk, NUM_SIZE_8);

    OPENSSL_free(str);

    //====================================================================//
    //  Deallocation
    //====================================================================//
    EVP_PKEY_free(evpk);
    EC_KEY_free(eck);
    BIO_free_all(outbio);

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//  Generate public key from private
////////////////////////////////////////////////////////////////////////////////
int GeneratePublicKey(
    const char * sk,
    uint8_t * pk
)
{
    EC_KEY * eck = NULL;
    EC_POINT * sec = NULL;
    const EC_GROUP * group = NULL;
    BIGNUM start;
    BIGNUM * res;
    BN_CTX * ctx;

    BN_init(&start);

    ctx = BN_CTX_new();

    res = &start;
    BN_hex2bn(&res, sk);

    eck = EC_KEY_new_by_curve_name(NID_secp256k1);
    group = EC_KEY_get0_group(eck);
    sec = EC_POINT_new(group);

    EC_KEY_set_private_key(eck, res);

    if (!EC_POINT_mul(group, sec, res, NULL, NULL, ctx))
    {
        printf("ERROR at EC_POINT_mul\n");
    }

    EC_KEY_set_public_key(eck, sec);

    const EC_GROUP * ecgrp = EC_KEY_get0_group(eck);

    //====================================================================//
    //  Public key extraction
    //====================================================================//
    const EC_POINT * pub = EC_KEY_get0_public_key(eck);

    char * str = EC_POINT_point2hex(
        ecgrp, pub, POINT_CONVERSION_COMPRESSED, NULL
    );

    int len = 0;

    if (str)
    {
        for ( ; str[len] != '\0'; ++len) {}
    }
    else
    {
        printf("ERROR\n");
        fflush(stdout);
    }

    HexStrToBigEndian(str, len, pk, PK_SIZE_8);

    //====================================================================//
    //  Deallocation
    //====================================================================//
    OPENSSL_free(str);
    BN_CTX_free(ctx);
    EC_KEY_free(eck);

    return 0;
}

// cryptography.cu
