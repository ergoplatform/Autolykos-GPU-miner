#ifndef REQUEST_H
#define REQUEST_H

/*******************************************************************************

    REQUEST -- Http requests handling

*******************************************************************************/

#include "definitions.h"
#include "jsmn.h"
#include <curl/curl.h>
#include <mutex>
#include <atomic>
// write function for curl http GET
size_t WriteFunc(
    void * ptr,
    size_t size,
    size_t nmemb,
    json_t * request
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
    json_t * oldreq,
    uint8_t * bound,
    uint8_t * mes,
    state_t * state,
    int * diff,
    bool checkPK,
    std::mutex& mut,
    std::atomic<unsigned int>& trigger
);

// curl http POST request
int PostPuzzleSolution(
    const char * to,
    const char * pkstr,
    const uint8_t * w,
    const uint8_t * nonce,
    const uint8_t * d
);

void CurlLogError(int curl_status, const char* message);


#endif // REQUEST_H
