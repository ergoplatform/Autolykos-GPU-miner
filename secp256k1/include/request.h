#ifndef REQUEST_H
#define REQUEST_H

/*******************************************************************************

    REQUEST -- Http requests handling

*******************************************************************************/

#include "definitions.h"
#include "jsmn.h"
#include <curl/curl.h>
#include <atomic>
#include <mutex>

// write function for CURL http GET
size_t WriteFunc(
    void * ptr,
    size_t size,
    size_t nmemb,
    json_t * request
);

// lowercase letters convert to uppercase
int ToUppercase(char * str);

// CURL log error 
void CurlLogError(CURLcode curl_status);

// Parse GET request data
int ParseRequest(
    json_t * oldreq ,
    json_t * newreq, 
    info_t *info, 
    int checkPubKey
);

// CURL http GET request
int GetLatestBlock(
    const char * from,
    json_t * oldreq,
    info_t * info,
    int checkPubKey
);

// CURL http POST request
int PostPuzzleSolution(
    const char * to,
    const char * pkstr,
    const uint8_t * w,
    const uint8_t * nonce,
    const uint8_t * d
);

#endif // REQUEST_H
