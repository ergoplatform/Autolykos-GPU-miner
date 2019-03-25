#ifndef REQUEST_H
#define REQUEST_H

/*******************************************************************************

    REQUEST -- Http requests handling

*******************************************************************************/

#include "definitions.h"

// initialize string for curl http GET
void InitString(
    string * str
);

// write function for curl http GET
size_t WriteFunc(
    void * ptr,
    size_t size,
    size_t nmemb,
    string * str
);

// curl http GET request
int GetLatestBlock(
    string * block,
    uint8_t * bound,
    uint8_t * mes,
    uint8_t * pk,
    uint8_t * state
);

// curl http POST request
int PostPuzzleSolution(
    uint8_t * w,
    uint8_t * nonce,
    uint8_t * d
);

#endif // REQUEST_H
