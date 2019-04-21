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
int ToUppercase(char * str);

// process termination handler
int TerminationRequestHandler(
    void
);

// curl http GET request
int GetLatestBlock(
    const char * from,
    json_t * oldreq,
    info_t * info,
    bool checkPK
);

// curl http POST request
int PostPuzzleSolution(
    const char * to,
    const char * pkstr,
    const uint8_t * w,
    const uint8_t * nonce,
    const uint8_t * d
);

void CurlLogError(CURLcode curl_status);


#endif // REQUEST_H
