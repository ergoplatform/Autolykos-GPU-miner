#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

/*******************************************************************************

    CRYPTOGRAPHY -- Key-pair handling with Openssl

*******************************************************************************/

#include "conversion.h"

// generate secret key from seed
int GenerateSecKey(
    const char * in,
    const int len,
    uint8_t * sk,
    char * skstr
);

// generate random key pair
int GenerateKeyPair(
    uint8_t * sk,
    uint8_t * pk
);

// generate public key from secret key
int GeneratePublicKey(
    const char * skstr,
    char * pkstr,
    uint8_t * pk
);

#endif // CRYPTOGRAPHY_H
