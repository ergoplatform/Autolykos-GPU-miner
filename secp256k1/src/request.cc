// request.cc

/*******************************************************************************

    REQUEST -- Http requests handling

*******************************************************************************/
#include "../include/easylogging++.h"
#include "../include/request.h"
#include "../include/conversion.h"
#include "../include/definitions.h"
#include "../include/jsmn.h"
#include <ctype.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <atomic>
#include <mutex>

//#ifndef _WIN32 
//#include <termios.h>
//#include <unistd.h>
//#endif

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
            LOG(ERROR) << "request cap > json capacity error in WriteFunc";
        }

        if (!(request->ptr = (char *)realloc(request->ptr, request->cap)))
        {
            LOG(ERROR) << "request ptr realloc error in WriteFunc";
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
    newreq.Reset();
    CURLcode curlError;
    int diff = 0;

    curl = curl_easy_init();
    
    if (!curl) { LOG(ERROR) << "Curl doesn't init in getblock"; }

    CurlLogError(curl_easy_setopt(curl, CURLOPT_URL, from));
    CurlLogError(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc));
    CurlLogError(curl_easy_setopt(curl, CURLOPT_WRITEDATA, &newreq));
    
    // set timeout to 10 sec so it doesn't hang up
    // waiting for default 5 minutes if url is unreachable / wrong 
    CurlLogError(curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L));
    CurlLogError(curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L));
    curlError = curl_easy_perform(curl);
    CurlLogError(curlError);
    curl_easy_cleanup(curl);
    VLOG(1) << "GET request " << newreq.ptr;
    
    // if curl returns error on request, don't change or check anything 
    if (!curlError)
    {
        ToUppercase(newreq.ptr);
        jsmn_init(&parser);
        jsmn_parse(&parser, newreq.ptr, newreq.len, newreq.toks, REQ_LEN);

        // no need to check node public key every time, i think
        if (checkPubKey)
        {   
            if (strncmp(info->pkstr, newreq.GetTokenStart(PK_POS), PK_SIZE_4))
            {
                LOG(ERROR)
                    << "Generated and received public keys do not match\n";
                
                fprintf(
                    stderr, "ABORT:  Public key derived from your secret key:\n"
                    "        0x%.2s",
                    info->pkstr
                );

                for (int i = 2; i < PK_SIZE_4; i += 16)
                {
                    fprintf(stderr, " %.16s", info->pkstr + i);
                }
            
                fprintf(
                    stderr,
                    "\n""        is not equal to the expected public key:\n"
                    "        0x%.2s", newreq.GetTokenStart(PK_POS)
                );

                for (int i = 2; i < PK_SIZE_4; i += 16)
                {
                    fprintf(stderr, " %.16s", newreq.GetTokenStart(PK_POS) + i);
                }

                fprintf(stderr, "\n");
                
                return EXIT_FAILURE;
            }
        }
 
        //====================================================================//
        //  Substitute message and change state when message changed
        //====================================================================//
        mesChanged = strncmp(
            oldreq->GetTokenStart(MES_POS), newreq.GetTokenStart(MES_POS),
            newreq.GetTokenLen(MES_POS)
        );
        
        int len = newreq.GetTokenLen(BOUND_POS);

        boundChanged = strncmp(
            oldreq->GetTokenStart(BOUND_POS), newreq.GetTokenStart(BOUND_POS),
            len
        );

        //check if we need to change ANYTHING, only then lock info mutex
        if (
            mesChanged || boundChanged || !(oldreq->len)
            || len != oldreq->GetTokenLen(BOUND_POS)
        )
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
            if (
                 !(oldreq->len) || len != oldreq->GetTokenLen(BOUND_POS)
                || boundChanged
            )
            {
                char buf[NUM_SIZE_4 + 1];

                DecStrToHexStrOf64(newreq.GetTokenStart(BOUND_POS), len, buf);
                HexStrToLittleEndian(buf, NUM_SIZE_4, info->bound, NUM_SIZE_8);

                diff = 1;
            }
            
            info->info_mutex.unlock();
            
            if (mesChanged || diff)
            {
                // signaling uint
                ++(info->blockId);
                LOG(INFO) << "Got new block in main thread";
            }
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
        LOG(ERROR) << "Curl doesn't initialize correctly in posting sol";
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
    
    // set timeout to 10 sec for sending solution
    CurlLogError(curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L));
    CurlLogError(curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L));    
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
