// request.cu

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

#ifndef _WIN32 
#include <termios.h>
#include <unistd.h>
#endif

#include <mutex>
#include <atomic>

////////////////////////////////////////////////////////////////////////////////
//  Write function for curl http GET
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

        //CALL(request->cap <= MAX_JSON_CAPACITY, ERROR_ALLOC);
        /*
        FUNCTION_CALL(
            request->ptr, (char *)realloc(request->ptr, request->cap),
            ERROR_ALLOC
        );
        */
        if(request->cap > MAX_JSON_CAPACITY)
        {
            LOG(ERROR) << "request cap > json capacity error in WriteFunc";
        }

        if(! (request->ptr = (char*) realloc(request->ptr, request->cap )))
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
int ToUppercase(
    char * str
)
{
    for (int i = 0; str[i] != '\0'; ++i)
    {
        str[i] = toupper(str[i]);
    }

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Process termination handler
////////////////////////////////////////////////////////////////////////////////
int TerminationRequestHandler(
    void
)
{
    // maybe we don't need this handler, cause everything will die properly on Ctrl-C
    // furthermore, on Windows it won't work (unix-specific termios stuff)
    // and with new additions, it doesn't stop on Ctrl-C, which is pretty bad


    #ifndef _WIN32
    
    // do nothing when in background
    if (getpgrp() != tcgetpgrp(STDOUT_FILENO))
    {
        return 0;
    }

    termios oldt;
    termios newt;
    int ch;
    int oldf;

    tcgetattr(STDIN_FILENO, &oldt);

    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);

    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);

    // terminating when any character is stroken
    if (ch == 'q' || ch == 'Q')
    {
        ungetc(ch, stdin);

        printf("Commencing termination\n");
        fflush(stdout);

        return 1;
    }
    
    // continue otherwise
    #endif
    return 0;
}


//CURL* curl;

void CurlLogError(int curl_status, const char* message)
{
    if(curl_status != CURLE_OK)
    {
        LOG(ERROR) << "Curl error " << curl_status << " in " << message;
    }

}



////////////////////////////////////////////////////////////////////////////////
//  Curl http GET request
////////////////////////////////////////////////////////////////////////////////
int GetLatestBlock(
    const char * from,
    json_t * oldreq,
    info_t * info,
    bool checkPK
)
{
    CURL * curl;
    json_t newreq(0, REQ_LEN);
    jsmn_parser parser;
    int changed = 0;
    int boundChanged = 0;
    //====================================================================//
    //  Get latest block
    //====================================================================//
    newreq.Reset();
    int curlError;
    int diff = 0;

    curl = curl_easy_init();
    
    if(!curl)
    {
        LOG(ERROR) << "Curl doesn't init in getblock";
    }
    curlError = curl_easy_setopt(curl, CURLOPT_URL, from);
    CurlLogError(curlError, "Setting curl URL");
    curlError = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc);
    CurlLogError(curlError, "Setting curl write function");
    curlError = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &newreq);
    CurlLogError(curlError, "Setting curl data pointer");
    
    // set timeout to 10sec so it doesn't hang up waiting for default 5 minutes if url is unreachable/wrong 

    curlError = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curlError = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curlError = curl_easy_perform(curl);
    CurlLogError(curlError, "Curl request");
    curl_easy_cleanup(curl);
    VLOG(1) << "GET request " << newreq.ptr;
    VLOG(1) << "Curl request status " << curlError;
    
    // if curl returns error on request, don't change or check anything 

    if(!curlError)
    {
        ToUppercase(newreq.ptr);
        jsmn_init(&parser);
        jsmn_parse(&parser, newreq.ptr, newreq.len, newreq.toks, REQ_LEN);
        // no need to check node public key every time, i think
        if(checkPK)
        {   
            if (strncmp(info->pkstr, newreq.GetTokenStart(PK_POS), PK_SIZE_4))
            {
                
                LOG(ERROR) << "Generated and received public keys do not match\n";
                
                
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
                    stderr, "\n""        is not equal to the expected public key:\n"
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
        //  Substitute message and change state in case message changed
        //====================================================================//
        
        changed = strncmp(
            oldreq->GetTokenStart(MES_POS), newreq.GetTokenStart(MES_POS),
            newreq.GetTokenLen(MES_POS)
        );
        
        int len = newreq.GetTokenLen(BOUND_POS);

        boundChanged = strncmp(
            oldreq->GetTokenStart(BOUND_POS), newreq.GetTokenStart(BOUND_POS),
            len
        );

        //check if we need to change ANYTHING, only then lock info mutex
        
        if( changed 
            || boundChanged
            || !(oldreq->len)
            || len != oldreq->GetTokenLen(BOUND_POS)
          )
        {
            
            info->info_mutex.lock();
            
            //====================================================================//
            //  Substitute message and change state in case message changed
            //====================================================================//
            
            
            
            if (!(oldreq->len) || changed)
            {
                 HexStrToBigEndian(
                 newreq.GetTokenStart(MES_POS), newreq.GetTokenLen(MES_POS),
                 info->mes_h, NUM_SIZE_8
                 );
            }


            //====================================================================//
            //  Substitute bound in case it changed
            //====================================================================//
            if (
                 !(oldreq->len)
                || len != oldreq->GetTokenLen(BOUND_POS)
                || boundChanged
                )
            {
                char buf[NUM_SIZE_4 + 1];

                DecStrToHexStrOf64(newreq.GetTokenStart(BOUND_POS), len, buf);
                HexStrToLittleEndian(buf, NUM_SIZE_4, info->bound_h, NUM_SIZE_8);

                diff = 1;
            }
            
            info->info_mutex.unlock();
        
            
            if(changed || diff)
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
//  Curl http POST request
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

    //====================================================================//
    //  Form message to post
    //====================================================================//
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
    //====================================================================//
    //  POST request
    //====================================================================//
    CURL * curl;
    curl = curl_easy_init();
    if(!curl)
    {
        LOG(ERROR) << "Curl doesn't initialize correctly in posting sol";
    }
    json_t respond(0, REQ_LEN);
    curl_slist * headers = NULL;
    curl_slist * tmp;
    int curlError;
    tmp = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(tmp, "Content-Type: application/json");

    curlError = curl_easy_setopt(curl, CURLOPT_URL, to);
    CurlLogError(curlError, "Setting curl URL post error");

 
    curlError = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curlError += curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
    
    // set timeout to 60 sec for sending solution
    curlError += curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 60L);
    curlError += curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);    
    curlError += curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc);
    curlError += curl_easy_setopt(curl, CURLOPT_WRITEDATA, &respond);
    CurlLogError(curlError, "POST options error");
    //PERSISTENT_CALL_STATUS(curl_easy_perform(curl), CURLE_OK);
    
    curlError = curl_easy_perform(curl);
    CurlLogError(curlError, "Posting solution error");


    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return EXIT_SUCCESS;
}

// request.cu
