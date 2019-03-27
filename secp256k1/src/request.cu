// request.cu

/*******************************************************************************

    REQUEST -- Http requests handling

*******************************************************************************/

#include "../include/request.h"
#include "../include/conversion.h"
#include "../include/jsmn.h"
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
//  Curl http GET request
////////////////////////////////////////////////////////////////////////////////
int GetLatestBlock(
    const uint8_t * pk,
    string_t * oldreq,
    jsmntok_t * oldtoks,
    uint8_t * bound,
    uint8_t * mes
)
{
    CURL * curl;
    CURLcode res;

    string_t newreq;
    jsmntok_t newtoks[7];
    jsmn_parser parser;

    uint8_t key[PK_SIZE_8];

    do 
    {
        curl = curl_easy_init();

        if (!curl)
        {
            return -1;
        }

        InitString(&newreq);

        curl_easy_setopt(
            curl, CURLOPT_URL, "http://188.166.89.71:9052/mining/candidate"
        );
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &newreq);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            fprintf(
                stderr, "ERROR: curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res)
            );

            fflush(stdout);

            return 1;
        }
        else
        {
            ///printf("%s\n", newreq.ptr);

            fflush(stdout);
        }

        curl_easy_cleanup(curl);

        jsmn_init(&parser);
        jsmn_parse(&parser, newreq.ptr, newreq.len, newtoks, 7);

        HexStrToBigEndian(
            newreq.ptr + newtoks[6].start, newtoks[6].end - newtoks[6].start,
            key, PK_SIZE_8
        );

        for (int i = 0; i < PK_SIZE_8; ++i)
        {
            if (key[i] != pk[i])
            {
                free(newreq.ptr);

                return 1;
            }
        }
    }
    while(oldreq->len && !strncmp(
        oldreq->ptr + oldtoks[2].start, newreq.ptr + newtoks[2].start,
        newtoks[2].end - newtoks[2].start
    ));

    free(oldreq->ptr);
    oldreq->ptr = newreq.ptr;
    oldreq->len = newreq.len;

    HexStrToBigEndian(
        newreq.ptr + newtoks[2].start, newtoks[2].end - newtoks[2].start,
        (uint8_t *)mes, NUM_SIZE_8
    );

    int len = newtoks[4].end - newtoks[4].start;

    if (
        !(oldreq->len)
        || len != oldtoks[4].end - oldtoks[4].start
        || strncmp(
            oldreq->ptr + oldtoks[4].start, newreq.ptr + newtoks[4].start, len
        )
    )
    {
        char tmp[NUM_SIZE_4 + 1];

        DecStrToHexStrOf64(
            newreq.ptr + newtoks[4].start, newtoks[4].end - newtoks[4].start,
            tmp
        );

        HexStrToLittleEndian(tmp, NUM_SIZE_4, bound, NUM_SIZE_8);
    }

    memcpy(oldtoks, newtoks, 7 * sizeof(jsmntok_t));

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//  Curl http POST request
////////////////////////////////////////////////////////////////////////////////
int PostPuzzleSolution(
    uint8_t * w,
    uint8_t * nonce,
    uint8_t * d
)
{
    uint32_t len;
    uint32_t pos = 6;

    char sol[256];

    //====================================================================//
    //  Form message to post
    //====================================================================//
    strcpy(sol, "{\"w\":\"");

    BigEndianToHexStr(w, PK_SIZE_8, sol + pos);
    pos += PK_SIZE_4;

    strcpy(sol + pos, "\",\"n\":\"");
    pos += 7;

    BigEndianToHexStr(nonce, NONCE_SIZE_8, sol + pos);
    pos += NONCE_SIZE_4;

    strcpy(sol + pos, "\",\"d\":");
    pos += 6;

    LittleEndianOf256ToDecStr(d, sol + pos, &len);
    pos += len;

    strcpy(sol + pos, "e0}\0");

    //====================================================================//
    //  POST request
    //====================================================================//
    CURL * curl;
    CURLcode res;

    curl = curl_easy_init();

    if (!curl)
    {
        return -1;
    }

    string_t str;
    InitString(&str);

    curl_slist * headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(
        curl, CURLOPT_URL, "http://188.166.89.71:9052/mining/solution"
    );

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, sol);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        fprintf(
            stderr, "ERROR: curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res)
        );

        fflush(stdout);
    }
    else
    {
        printf("Solution posted successfully\n");

        fflush(stdout);
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return 0;
}

// request.cu
