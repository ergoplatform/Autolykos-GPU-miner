// request.cc

/*******************************************************************************

    REQUEST -- Http requests handling

*******************************************************************************/

#include "../include/conversion.h"
#include "../include/definitions.h"
#include "../include/easylogging++.h"
#include "../include/jsmn.h"
#include "../include/processing.h"
#include "../include/request.h"
#include <ctype.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <atomic>
#include <mutex>

////////////////////////////////////////////////////////////////////////////////
//  Write function for CURL http GET
////////////////////////////////////////////////////////////////////////////////
size_t WriteFunc(
    void * ptr,
    size_t size,
    size_t nmemb,
    json_t * request
)
{
    size_t newlen = request->len + size * nmemb;

    if (newlen > request->cap)
    {
        request->cap = (newlen << 1) + 1;

        if (request->cap > MAX_JSON_CAPACITY)
        {
            LOG(ERROR) << "Request capacity exceeds json capacity in WriteFunc";
        }

        if (!(request->ptr = (char *)realloc(request->ptr, request->cap)))
        {
            LOG(ERROR) << "Request pointer realloc failed in WriteFunc";
        } 
    }

    memcpy(request->ptr + request->len, ptr, size * nmemb);

    request->ptr[newlen] = '\0';
    request->len = newlen;

    return size * nmemb;
}

////////////////////////////////////////////////////////////////////////////////
//  Lowercase letters convert to uppercase
////////////////////////////////////////////////////////////////////////////////
int ToUppercase(char * str)
{
    for (int i = 0; str[i] != '\0'; ++i) { str[i] = toupper(str[i]); }

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  CURL log error 
////////////////////////////////////////////////////////////////////////////////
void CurlLogError(CURLcode curl_status)
{
    if (curl_status != CURLE_OK)
    {
        LOG(ERROR) << "CURL: " << curl_easy_strerror(curl_status);
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  CURL http GET request
////////////////////////////////////////////////////////////////////////////////
int GetLatestBlock(
    const char * from,
    json_t * oldreq,
    info_t * info,
    int checkPubKey
)
{
    CURL * curl;
    json_t newreq(0, REQ_LEN);
    jsmn_parser parser;

    int mesChanged = 0;
    int boundChanged = 0;

    //========================================================================//
    //  Get latest block
    //========================================================================//
    CURLcode curlError;

    curl = curl_easy_init();
    if (!curl) { LOG(ERROR) << "CURL initialization failed in GetLatestBlock"; }

    CurlLogError(curl_easy_setopt(curl, CURLOPT_URL, from));
    CurlLogError(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc));
    CurlLogError(curl_easy_setopt(curl, CURLOPT_WRITEDATA, &newreq));
    
    // set timeout to 30 sec so it doesn't hang up
    // waiting for default 5 minutes if url is unreachable / wrong 
    CurlLogError(curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L));
    CurlLogError(curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L));
    curlError = curl_easy_perform(curl);
    CurlLogError(curlError);
    curl_easy_cleanup(curl);

    VLOG(1) << "GET request " << newreq.ptr;
    
    // if curl returns error on request, do not change or check anything 
    if (!curlError)
    {
        ToUppercase(newreq.ptr);
        jsmn_init(&parser);
        
        int jsmn_result = jsmn_parse(
            &parser, newreq.ptr, newreq.len, newreq.toks, REQ_LEN
        );

        if (jsmn_result < 0)
        {
            LOG(ERROR) << "Jsmn failed to parse latest block";
            LOG(ERROR) << "Block data: " << newreq.ptr;

            return EXIT_FAILURE;
        }

        // no need to check node public key every time
        if (checkPubKey)
        {   
            if (strncmp(info->pkstr, newreq.GetTokenStart(PK_POS), PK_SIZE_4))
            {
                char logstr[1000];

                LOG(ERROR)
                    << "Generated and received public keys do not match";
                
                PrintPublicKey(info->pkstr, logstr);
                LOG(ERROR) << "Generated public key:\n   " << logstr;
            
                PrintPublicKey(newreq.GetTokenStart(PK_POS), logstr);
                LOG(ERROR) << "Received public key:\n   " << logstr;

                exit(EXIT_FAILURE);
            }
        }
 
        //====================================================================//
        //  Substitute message and change state when message changed
        //====================================================================//
        int mesLen = newreq.GetTokenLen(MES_POS);
        int boundLen = newreq.GetTokenLen(BOUND_POS);       
        
        if (oldreq->len)
        {
            if (mesLen != oldreq->GetTokenLen(MES_POS)) { mesChanged = 1; }
            else
            {
                mesChanged = strncmp(
                    oldreq->GetTokenStart(MES_POS),
                    newreq.GetTokenStart(MES_POS),
                    mesLen
                );
            }

            if (boundLen != oldreq->GetTokenLen(BOUND_POS))
            {
                boundChanged = 1;
            }
            else
            {
                boundChanged = strncmp(
                    oldreq->GetTokenStart(BOUND_POS),
                    newreq.GetTokenStart(BOUND_POS),
                    boundLen
                );
            }
        }

        // check if we need to change anything, only then lock info mutex
        if (mesChanged || boundChanged || !(oldreq->len))
        {
            info->info_mutex.lock();
            
            //================================================================//
            //  Substitute message and change state when message changed
            //================================================================//
            if (!(oldreq->len) || mesChanged)
            {
                 HexStrToBigEndian(
                     newreq.GetTokenStart(MES_POS), newreq.GetTokenLen(MES_POS),
                     info->mes, NUM_SIZE_8
                 );
            }

            //================================================================//
            //  Substitute bound in case it changed
            //================================================================//
            if (!(oldreq->len) || boundChanged)
            {
                char buf[NUM_SIZE_4 + 1];

                DecStrToHexStrOf64(
                    newreq.GetTokenStart(BOUND_POS),
                    newreq.GetTokenLen(BOUND_POS),
                    buf
                );

                HexStrToLittleEndian(buf, NUM_SIZE_4, info->bound, NUM_SIZE_8);
            }
            
            info->info_mutex.unlock();
            
            // signaling uint
            ++(info->blockId);
            LOG(INFO) << "Got new block in main thread";
        }

        //====================================================================//
        //  Substitute old block with newly read
        //====================================================================//
        *oldreq = newreq;
        newreq.ptr = NULL;
        newreq.toks = NULL;

        return EXIT_SUCCESS;
    }
    
    return EXIT_FAILURE;
}

////////////////////////////////////////////////////////////////////////////////
//  CURL http POST request
////////////////////////////////////////////////////////////////////////////////
int PostPuzzleSolution(
    const char * to,
    const char * pkstr,
    const uint8_t * w,
    const uint8_t * nonce,
    const uint8_t * d
)
{
    uint32_t len;
    uint32_t pos = 0;

    char request[JSON_CAPACITY];

    //========================================================================//
    //  Form message to post
    //========================================================================//
    strcpy(request + pos, "{\"pk\":\"");
    pos += 7;

    strcpy(request + pos, pkstr);
    pos += PK_SIZE_4;

    strcpy(request + pos, "\",\"w\":\"");
    pos += 7;

    BigEndianToHexStr(w, PK_SIZE_8, request + pos);
    pos += PK_SIZE_4;

    strcpy(request + pos, "\",\"n\":\"");
    pos += 7;

    LittleEndianToHexStr(nonce, NONCE_SIZE_8, request + pos);
    pos += NONCE_SIZE_4;

    strcpy(request + pos, "\",\"d\":");
    pos += 6;

    LittleEndianOf256ToDecStr(d, request + pos, &len);
    pos += len;

    strcpy(request + pos, "e0}\0");

    VLOG(1) << "POST request " << request;

    //========================================================================//
    //  POST request
    //========================================================================//
    CURL * curl;
    curl = curl_easy_init();

    if (!curl)
    {
        LOG(ERROR) << "CURL initialization failed in PostPuzzleSolution";
    }

    json_t respond(0, REQ_LEN);
    curl_slist * headers = NULL;
    curl_slist * tmp;
    CURLcode curlError;
    tmp = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(tmp, "Content-Type: application/json");

    CurlLogError(curl_easy_setopt(curl, CURLOPT_URL, to));
    CurlLogError(curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers));;
    CurlLogError(curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request));
    
    // set timeout to 30 sec for sending solution
    CurlLogError(curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L));
    CurlLogError(curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L));    
    CurlLogError(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc));
    CurlLogError(curl_easy_setopt(curl, CURLOPT_WRITEDATA, &respond));

    int retries = 0;

    do
    {
        curlError = curl_easy_perform(curl);
        ++retries;
    }
    while (retries < MAX_POST_RETRIES && curlError != CURLE_OK);

    CurlLogError(curlError);

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return EXIT_SUCCESS;
}

// request.cc
