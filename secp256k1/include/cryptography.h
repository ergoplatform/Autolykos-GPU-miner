#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

/*******************************************************************************

    CRYPTOGRAPHY -- Key-pair handling with Openssl

*******************************************************************************/

#include "conversion.h"

// generate key pair
int GenerateKeyPair(
    uint8_t * sk,
    uint8_t * pk
);

// generate public key from private
int GeneratePublicKey(
    const char * sk,
    uint8_t * pk
);

#endif // CRYPTOGRAPHY_H
