    
#ifndef PROCESSING_H
#define PROCESSING_H

/*******************************************************************************
    PROCESSING -- Puzzle cycle execution support
*******************************************************************************/

#include "definitions.h"

// read config file
int ReadConfig(
    const char * fileName,
    uint8_t * sk,
    char * skstr,
    char * from,
    char * to,
    int * keep
);

// print public key
int PrintPublicKey(const char * pkstr, char * str);

int PrintPublicKey(const uint8_t * pk, char * str);

// print Autolukos puzzle solution
int PrintPuzzleSolution(
    const uint8_t * nonce,
    const uint8_t * sol,
    char * str
);

#endif // PROCESSING_H
