#ifndef PROCESSING_H
#define PROCESSING_H

/*******************************************************************************

    PROCESSING -- puzzle cycle execution support

*******************************************************************************/

#include "definitions.h"

//// time stamp
//char * TimeStamp(
//    timestamp_t * stamp
//);
 
// find file size
long int FindFileSize(
    const char * filename
);

// read config file
int ReadConfig(
    const char * filename,
    uint8_t * sk,
    char * skstr,
    char * from,
    char * to,
    int * keep//,
    //timestamp_t * stamp
);

// print Autolukos puzzle state variables
int PrintPuzzleState(
    const uint8_t * mes,
    const uint8_t * pk,
    const uint8_t * sk,
    const uint8_t * w,
    const uint8_t * x,
    const uint8_t * bound//,
    //timestamp_t * stamp
);

// print Autolukos puzzle solution
int PrintPuzzleSolution(
    const uint8_t * nonce,
    const uint8_t * sol
);

#endif // PROCESSING_H
