// request.cu

/*******************************************************************************

    REQUEST -- Http requests handling

*******************************************************************************/

#include "../include/request.h"
#include "../include/conversion.h"
#include "../include/definitions.h"
#include "../include/jsmn.h"
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

////////////////////////////////////////////////////////////////////////////////
//  Initialize string for curl http GET
////////////////////////////////////////////////////////////////////////////////
void InitString(
    string_t * str
)
{
    str->len = 0;
    str->ptr = (char *)malloc(1);

    if (!(str->ptr))
    {
        fprintf(stderr, "ERROR: malloc() failed\n");
        exit(EXIT_FAILURE);
    }

    str->ptr[0] = '\0';

    return;
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

    str->ptr = (char *)realloc(str->ptr, nlen + 1);

    if (!(str->ptr))
    {
        fprintf(stderr, "ERROR: realloc() failed\n");
        exit(EXIT_FAILURE);
    }

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

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//  Curl http GET request
////////////////////////////////////////////////////////////////////////////////
int GetLatestBlock(
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
    jsmntok_t newtoks[T_LEN];
    jsmn_parser parser;

    int changed = 0;

    do 
    {
        FUNCTION_CALL(curl, curl_easy_init(), ERROR_CURL);

        InitString(&newreq);

        curl_easy_setopt(
            curl, CURLOPT_URL, "http://188.166.89.71:9052/mining/candidate"
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

        if (strncmp(pkstr, newreq.ptr + newtoks[PK_POS].start, PK_SIZE_4))
        {
            free(newreq.ptr);

            return 1;
        }
    }
    while(
        oldreq->len
        && !(changed = strncmp(
            oldreq->ptr + oldtoks[MES_POS].start,
            newreq.ptr + newtoks[MES_POS].start,
            newtoks[MES_POS].end - newtoks[MES_POS].start
        ))
        && *state != STATE_CONTINUE
    );

    if (!(oldreq->len) || changed)
    {
        HexStrToBigEndian(
            newreq.ptr + newtoks[MES_POS].start,
            newtoks[MES_POS].end - newtoks[MES_POS].start,
            (uint8_t *)mes, NUM_SIZE_8
        );

        *state = STATE_REHASH;
    }

    int len = newtoks[BOUND_POS].end - newtoks[BOUND_POS].start;

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

    free(oldreq->ptr);
    oldreq->ptr = newreq.ptr;
    oldreq->len = newreq.len;
    memcpy(oldtoks, newtoks, T_LEN * sizeof(jsmntok_t));

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//  Curl http POST request
////////////////////////////////////////////////////////////////////////////////
int PostPuzzleSolution(
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
            curl, CURLOPT_URL, "http://188.166.89.71:9052/mining/solution"
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

    return 0;
}

// request.cu
