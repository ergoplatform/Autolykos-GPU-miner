#ifndef PROCESSING_H
#define PROCESSING_H

/*******************************************************************************

    PROCESSING -- Puzzle cycle execution support

*******************************************************************************/

#include "definitions.h"
// token equality checker
int jsoneq(const char *json, jsmntok_t *tok, const char *s);

// find file size
long int FindFileSize(const char * fileName);

// read config file
int ReadConfig(
    const char * fileName,
    uint8_t * sk,
    char * skstr,
    char * from,
    char * to,
    int * keep
);

// print Autolukos puzzle state variables
int PrintPuzzleState(
    const uint8_t * mes,
    const uint8_t * pk,
    const uint8_t * sk,
    const uint8_t * w,
    const uint8_t * x,
    const uint8_t * bound
);

// print Autolukos puzzle solution
int PrintPuzzleSolution(
    const uint8_t * nonce,
    const uint8_t * sol
);

#endif // PROCESSING_H
