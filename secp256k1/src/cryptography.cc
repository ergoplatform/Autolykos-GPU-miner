// cryptography.cc

/*******************************************************************************

    CRYPTOGRAPHY -- Key-pair handling with OpenSSL

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
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <random>

////////////////////////////////////////////////////////////////////////////////
//  Generate secret key from seed
////////////////////////////////////////////////////////////////////////////////
int GenerateSecKey(
    const char * in,
    const int len,
    uint8_t * sk,
    char * skstr
)
{
    ctx_t ctx;
    uint64_t aux[32];

    //====================================================================//
    //  Initialize context
    //====================================================================//
    memset(ctx.b, 0, 128);
    B2B_IV(ctx.h);
    ctx.h[0] ^= 0x01010000 ^ NUM_SIZE_8;
    memset(ctx.t, 0, 16);
    ctx.c = 0;

    //====================================================================//
    //  Hash message
    //====================================================================//
    for (int i = 0; i < len; ++i)
    {
        if (ctx.c == 128) { HOST_B2B_H(&ctx, aux); }

        ctx.b[ctx.c++] = (uint8_t)(in[i]);
    }

    HOST_B2B_H_LAST(&ctx, aux);

    for (int i = 0; i < NUM_SIZE_8; ++i)
    {
        sk[NUM_SIZE_8 - i - 1] = (ctx.h[i >> 3] >> ((i & 7) << 3)) & 0xFF;
    }

    //====================================================================//
    //  Mod Q
    //====================================================================//
    uint8_t borrow[2];

    borrow[0] = ((uint64_t *)sk)[0] < Q0;
    aux[0] = ((uint64_t *)sk)[0] - Q0;

    borrow[1] = ((uint64_t *)sk)[1] < Q1 + borrow[0];
    aux[1] = ((uint64_t *)sk)[1] - Q1 - borrow[0];

    borrow[0] = ((uint64_t *)sk)[2] < Q2 + borrow[1];
    aux[2] = ((uint64_t *)sk)[2] - Q2 - borrow[1];

    borrow[1] = ((uint64_t *)sk)[3] < Q3 + borrow[0];
    aux[3] = ((uint64_t *)sk)[3] - Q3 - borrow[0];

    if (!(borrow[1] || borrow[0])) { memcpy(sk, aux, NUM_SIZE_8); }

    // convert secret key to hex string
    LittleEndianToHexStr(sk, NUM_SIZE_8, skstr);

    return EXIT_SUCCESS;
}


int GenerateSecKeyNew(
    const char * in,
    const int len,
    uint8_t * sk,
    char * skstr,
    char * passphrase
)
{
    unsigned char digest[NUM_SIZE_4];
    char salt[1024] = "mnemonic";
    strcat(salt, passphrase);
    PKCS5_PBKDF2_HMAC(in, len, (unsigned char*)salt, strlen(salt), 2048, EVP_sha512(), NUM_SIZE_4, digest);
    
    uint_t hmaclen = NUM_SIZE_4;
    char key[] = "Bitcoin seed";
    unsigned char result[NUM_SIZE_4];
    
    #if OPENSSL_VERSION_NUMBER < 0x10100000L

        HMAC_CTX ctx;
        HMAC_CTX_init(&ctx);
    
        HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha512(), NULL);
        HMAC_Update(&ctx, digest, NUM_SIZE_4);
        HMAC_Final(&ctx, result, &hmaclen);
        HMAC_CTX_cleanup(&ctx);
            
        memcpy(sk, result, sizeof(uint8_t)*NUM_SIZE_8);
        
        LittleEndianToHexStr(sk, NUM_SIZE_8, skstr);
        HexStrToBigEndian(skstr, NUM_SIZE_4, sk, NUM_SIZE_8);
        LittleEndianToHexStr(sk, NUM_SIZE_8, skstr);

    #else 
        HMAC_CTX *ctx = HMAC_CTX_new();
    
        HMAC_Init_ex(ctx, key, strlen(key), EVP_sha512(), NULL);
        HMAC_Update(ctx, digest, NUM_SIZE_4);
        HMAC_Final(ctx, result, &hmaclen);
            
        memcpy(sk, result, sizeof(uint8_t)*NUM_SIZE_8);
        HMAC_CTX_free(ctx);
        LittleEndianToHexStr(sk, NUM_SIZE_8, skstr);
        HexStrToBigEndian(skstr, NUM_SIZE_4, sk, NUM_SIZE_8);
        LittleEndianToHexStr(sk, NUM_SIZE_8, skstr);

    #endif
    return EXIT_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////
//  Generate random key pair
////////////////////////////////////////////////////////////////////////////////
int GenerateKeyPair(uint8_t * sk, uint8_t * pk)
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
//  Generate public key from secret key
////////////////////////////////////////////////////////////////////////////////
int GeneratePublicKey(
    const char * skstr,
    char * pkstr,
    uint8_t * pk
)
{
    EC_KEY * eck = NULL;
    EC_POINT * sec = NULL;
    BIGNUM * res;
    BN_CTX * ctx;


    FUNCTION_CALL(ctx, BN_CTX_new(), ERROR_OPENSSL);

    res = BN_new();
    
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
    BN_free(res);
    EC_KEY_free(eck);

    return EXIT_SUCCESS;
}

//-----------------------
//--check std::random_device for different results
//---------
int checkRandomDevice()
{
    std::random_device rd1;
    std::random_device rd2;
    if(rd1() == rd2()) return EXIT_FAILURE;
    if(rd1() == rd2()) return EXIT_FAILURE;

    return EXIT_SUCCESS;

}


// cryptography.cc
