#ifndef REQUEST_H
#define REQUEST_H

/*******************************************************************************

    REQUEST -- Http requests handling

*******************************************************************************/

#include "definitions.h"
#include "jsmn.h"

// initialize string_t for curl http GET
void InitString(
    string_t * str
);

// write function for curl http GET
size_t WriteFunc(
    void * ptr,
    size_t size,
    size_t nmemb,
    string_t * str
);

// curl http GET request
int GetLatestBlock(
    const uint8_t * pk,
    string_t * oldreq,
    jsmntok_t * oldtoks,
    uint8_t * bound,
    uint8_t * mes
);

// curl http POST request
int PostPuzzleSolution(
    uint8_t * w,
    uint8_t * nonce,
    uint8_t * d
);

#endif // REQUEST_H
