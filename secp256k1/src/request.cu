// request.cu

/*******************************************************************************

    REQUEST -- Http requests handling

*******************************************************************************/

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
#include <termios.h>
#include <unistd.h>

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

        CALL(request->cap <= MAX_JSON_CAPACITY, ERROR_ALLOC);

        FUNCTION_CALL(
            request->ptr, (char *)realloc(request->ptr, request->cap),
            ERROR_ALLOC
        );
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
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//  Curl http GET request
////////////////////////////////////////////////////////////////////////////////
int GetLatestBlock(
    const char * from,
    const char * pkstr,
    json_t * oldreq,
    uint8_t * bound,
    uint8_t * mes,
    state_t * state,
    int * diff
)
{
    CURL * curl;
    json_t newreq(0, REQ_LEN);
    jsmn_parser parser;
    int changed = 0;

    //====================================================================//
    //  Get latest block
    //====================================================================//
    do 
    {
        newreq.Reset();

        if (TerminationRequestHandler())
        {
            *state = STATE_INTERRUPT;
            return EXIT_SUCCESS;
        }

        PERSISTENT_FUNCTION_CALL(curl, curl_easy_init());

        PERSISTENT_CALL_STATUS(
            curl_easy_setopt(curl, CURLOPT_URL, from), CURLE_OK
        );

        PERSISTENT_CALL_STATUS(
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc),
            CURLE_OK
        );

        PERSISTENT_CALL_STATUS(
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &newreq),
            CURLE_OK
        );

        PERSISTENT_CALL_STATUS(curl_easy_perform(curl), CURLE_OK);

        curl_easy_cleanup(curl);

        ToUppercase(newreq.ptr);

        jsmn_init(&parser);
        jsmn_parse(&parser, newreq.ptr, newreq.len, newreq.toks, REQ_LEN);

        /// to do /// checking obtained message
        // key-pair is not valid
        if (strncmp(pkstr, newreq.GetTokenStart(PK_POS), PK_SIZE_4))
        {
            fprintf(
                stderr, "ABORT:  Public key derived from your secret key:\n"
                "        0x%.2s",
                pkstr
            );

            for (int i = 2; i < PK_SIZE_4; i += 16)
            {
                fprintf(stderr, " %.16s", pkstr + i);
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
    // repeat if solution is already posted and block is still not changed  
    while(
        oldreq->len
        && !(changed = strncmp(
            oldreq->GetTokenStart(MES_POS), newreq.GetTokenStart(MES_POS),
            newreq.GetTokenLen(MES_POS)
        ))
        && *state != STATE_CONTINUE
    );

    //====================================================================//
    //  Substitute message and change state in case message changed
    //====================================================================//
    if (!(oldreq->len) || changed)
    {
        HexStrToBigEndian(
            newreq.GetTokenStart(MES_POS), newreq.GetTokenLen(MES_POS),
            mes, NUM_SIZE_8
        );

        *state = STATE_REHASH;
    }

    int len = newreq.GetTokenLen(BOUND_POS);

    //====================================================================//
    //  Substitute bound in case it changed
    //====================================================================//
    if (
        !(oldreq->len)
        || len != oldreq->GetTokenLen(BOUND_POS)
        || strncmp(
            oldreq->GetTokenStart(BOUND_POS), newreq.GetTokenStart(BOUND_POS),
            len
        )
    )
    {
        char buf[NUM_SIZE_4 + 1];

        DecStrToHexStrOf64(newreq.GetTokenStart(BOUND_POS), len, buf);
        HexStrToLittleEndian(buf, NUM_SIZE_4, bound, NUM_SIZE_8);

        *diff = 1;
    }

    //====================================================================//
    //  Substitute old block with newly read
    //====================================================================//
    *oldreq = newreq;
    newreq.ptr = NULL;
    newreq.toks = NULL;

    return EXIT_SUCCESS;
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

    //====================================================================//
    //  POST request
    //====================================================================//
    CURL * curl;

    PERSISTENT_FUNCTION_CALL(curl, curl_easy_init());

    json_t respond(0, REQ_LEN);
    curl_slist * headers = NULL;
    curl_slist * tmp;

    PERSISTENT_FUNCTION_CALL(
        tmp, curl_slist_append(headers, "Accept: application/json")
    );

    PERSISTENT_FUNCTION_CALL(
        headers, curl_slist_append(tmp, "Content-Type: application/json")
    );

    PERSISTENT_CALL_STATUS(curl_easy_setopt(curl, CURLOPT_URL, to), CURLE_OK);

    PERSISTENT_CALL_STATUS(
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers), CURLE_OK
    );

    PERSISTENT_CALL_STATUS(
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request), CURLE_OK
    );

    PERSISTENT_CALL_STATUS(
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc), CURLE_OK
    );

    PERSISTENT_CALL_STATUS(
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &respond), CURLE_OK
    );

    PERSISTENT_CALL_STATUS(curl_easy_perform(curl), CURLE_OK);

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return EXIT_SUCCESS;
}

// request.cu
