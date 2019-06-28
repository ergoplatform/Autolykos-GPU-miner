#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

/*******************************************************************************

    CRYPTOGRAPHY -- Key-pair handling with OpenSSL

*******************************************************************************/

#include "conversion.h"

// generate secret key from seed
int GenerateSecKey(
    const char * in,
    const int len,
    uint8_t * sk,
    char * skstr
);

// generate secret key from string - bitcoin algorithm
int GenerateSecKeyNew(
    const char * in,
    const int len,
    uint8_t * sk,
    char * skstr,
    char * message
);

// generate random key pair
int GenerateKeyPair(uint8_t * sk, uint8_t * pk);

// generate public key from secret key
int GeneratePublicKey(
    const char * skstr,
    char * pkstr,
    uint8_t * pk
);

// check if random device works OK
int checkRandomDevice();

#endif // CRYPTOGRAPHY_H
