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
//  Initialize string for curl http GET
////////////////////////////////////////////////////////////////////////////////
int InitString(
    string_t * str
)
{
    str->len = 0;

    FUNCTION_CALL(str->ptr, (char *)malloc(1), ERROR_ALLOC);

    str->ptr[0] = '\0';

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Write function for curl http GET
////////////////////////////////////////////////////////////////////////////////
size_t WriteFunc(
    void * ptr,
    size_t size,
    size_t nmemb,
    string_t * str
)
{
    size_t nlen = str->len + size * nmemb;

    FUNCTION_CALL(str->ptr, (char *)realloc(str->ptr, nlen + 1), ERROR_ALLOC);

    memcpy(str->ptr + str->len, ptr, size * nmemb);

    str->ptr[nlen] = '\0';
    str->len = nlen;

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
    if (ch != EOF)
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
    const string_t * config,
    const jsmntok_t * conftoks,
    const char * pkstr,
    string_t * oldreq,
    jsmntok_t * oldtoks,
    uint8_t * bound,
    uint8_t * mes,
    state_t * state
)
{
    CURL * curl;

    string_t newreq;
    newreq.ptr = NULL;

    jsmntok_t newtoks[T_LEN];
    jsmn_parser parser;

    int changed = 0;

    //====================================================================//
    //  Get latest block
    //====================================================================//
    do 
    {
        if (newreq.ptr)
        {
            free(newreq.ptr);
            newreq.ptr = NULL;
        }

        if (TerminationRequestHandler())
        {
            *state = STATE_INTERRUPT;
            return EXIT_SUCCESS;
        }

        FUNCTION_CALL(curl, curl_easy_init(), ERROR_CURL);

        InitString(&newreq);

        curl_easy_setopt(
            curl, CURLOPT_URL, config->ptr + conftoks[FROM_POS].start
        );

        CALL_STATUS(
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc),
            ERROR_CURL, CURLE_OK
        );

        CALL_STATUS(
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &newreq),
            ERROR_CURL, CURLE_OK
        );

        CALL_STATUS(curl_easy_perform(curl), ERROR_CURL, CURLE_OK);

        ToUppercase(newreq.ptr);

        curl_easy_cleanup(curl);

        jsmn_init(&parser);
        jsmn_parse(&parser, newreq.ptr, newreq.len, newtoks, T_LEN);

        // key-pair is not valid
        if (strncmp(pkstr, newreq.ptr + newtoks[PK_POS].start, PK_SIZE_4))
        {
            fprintf(
                stderr,
                "ABORT:  Public key derived from your secret key:\n"
                "        0x%.2s",
                pkstr
            );

            for (int i = 2; i < PK_SIZE_4; i += 16)
            {
                fprintf(stderr, " %.16s", pkstr + i);
            }
            
            fprintf(
                stderr,
                "\n"
                "        is not equal to the expected public key:\n"
                "        0x%.2s",
                newreq.ptr + newtoks[PK_POS].start
            );

            for (int i = 2; i < PK_SIZE_4; i += 16)
            {
                fprintf(
                    stderr, " %.16s", newreq.ptr + newtoks[PK_POS].start + i
                );
            }

            fprintf(stderr, "\n");

            if (newreq.ptr)
            {
                free(newreq.ptr);
                newreq.ptr = NULL;
            }

            return EXIT_FAILURE;
        }
    }
    // repeat if solution is already posted and block is still not changed  
    while(
        oldreq->len
        && !(changed = strncmp(
            oldreq->ptr + oldtoks[MES_POS].start,
            newreq.ptr + newtoks[MES_POS].start,
            newtoks[MES_POS].end - newtoks[MES_POS].start
        ))
        && *state != STATE_CONTINUE
    );

    //====================================================================//
    //  Substitute message and change state in case message changed
    //====================================================================//
    if (!(oldreq->len) || changed)
    {
        HexStrToBigEndian(
            newreq.ptr + newtoks[MES_POS].start,
            newtoks[MES_POS].end - newtoks[MES_POS].start,
            mes, NUM_SIZE_8
        );

        *state = STATE_REHASH;
    }

    int len = newtoks[BOUND_POS].end - newtoks[BOUND_POS].start;

    //====================================================================//
    //  Substitute bound in case it changed
    //====================================================================//
    if (
        !(oldreq->len)
        || len != oldtoks[BOUND_POS].end - oldtoks[BOUND_POS].start
        || strncmp(
            oldreq->ptr + oldtoks[BOUND_POS].start,
            newreq.ptr + newtoks[BOUND_POS].start, len
        )
    )
    {
        char buf[NUM_SIZE_4 + 1];

        DecStrToHexStrOf64(
            newreq.ptr + newtoks[BOUND_POS].start,
            newtoks[BOUND_POS].end - newtoks[BOUND_POS].start,
            buf
        );

        HexStrToLittleEndian(buf, NUM_SIZE_4, bound, NUM_SIZE_8);
    }

    //====================================================================//
    //  Substitute old block with newly read
    //====================================================================//
    free(oldreq->ptr);
    oldreq->ptr = newreq.ptr;
    oldreq->len = newreq.len;
    memcpy(oldtoks, newtoks, T_LEN * sizeof(jsmntok_t));

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Curl http POST request
////////////////////////////////////////////////////////////////////////////////
int PostPuzzleSolution(
    const string_t * config,
    const jsmntok_t * conftoks,
    const char * pkstr,
    const uint8_t * w,
    const uint8_t * nonce,
    const uint8_t * d
)
{
    uint32_t len;
    uint32_t pos = 0;

    char request[256];

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

    BigEndianToHexStr(nonce, NONCE_SIZE_8, request + pos);
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

    FUNCTION_CALL(curl, curl_easy_init(), ERROR_CURL);

    string_t respond;
    InitString(&respond);

    curl_slist * headers = NULL;
    curl_slist * tmp;

    FUNCTION_CALL(
        tmp, curl_slist_append(headers, "Accept: application/json"), ERROR_CURL
    );

    FUNCTION_CALL(
        headers, curl_slist_append(tmp, "Content-Type: application/json"),
        ERROR_CURL
    );

    CALL_STATUS(
        curl_easy_setopt(
            curl, CURLOPT_URL, config->ptr + conftoks[TO_POS].start
        ),
        ERROR_CURL, CURLE_OK
    );

    CALL_STATUS(
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers), ERROR_CURL,
        CURLE_OK
    );

    CALL_STATUS(
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request), ERROR_CURL,
        CURLE_OK
    );

    CALL_STATUS(
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc), ERROR_CURL,
        CURLE_OK
    );

    CALL_STATUS(
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &respond), ERROR_CURL,
        CURLE_OK
    );

    CALL_STATUS(curl_easy_perform(curl), ERROR_CURL, CURLE_OK);

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return EXIT_SUCCESS;
}

// request.cu
