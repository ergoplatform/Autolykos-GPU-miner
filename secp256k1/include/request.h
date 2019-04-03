#ifndef REQUEST_H
#define REQUEST_H

/*******************************************************************************

    REQUEST -- Http requests handling

*******************************************************************************/

#include "definitions.h"
#include "jsmn.h"

// initialize string_t for curl http GET
int InitString(
    string_t * str
);

// write function for curl http GET
size_t WriteFunc(
    void * ptr,
    size_t size,
    size_t nmemb,
    string_t * str
);

// lowercase letters convert to uppercase
int ToUppercase(
    char * str
);

// process termination handler
int TerminationRequestHandler(
    void
);

// curl http GET request
int GetLatestBlock(
    const char * from,
    const char * pkstr,
    string_t * oldreq,
    jsmntok_t * oldtoks,
    uint8_t * bound,
    uint8_t * mes,
    state_t * state,
    int * diff
);

// curl http POST request
int PostPuzzleSolution(
    const char * to,
    const char * pkstr,
    const uint8_t * w,
    const uint8_t * nonce,
    const uint8_t * d
);

#endif // REQUEST_H
