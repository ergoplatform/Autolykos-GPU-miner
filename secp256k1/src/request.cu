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
    string * str
)
{
    str->len = 0;
    str->ptr = (char *)malloc(1);

    if (str->ptr == NULL)
    {
        fprintf(stderr, "malloc() failed\n");
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
    string * str
)
{
    size_t nlen = str->len + size * nmemb;

    str->ptr = (char *)realloc(str->ptr, nlen + 1);

    if (str->ptr == NULL)
    {
        fprintf(stderr, "realloc() failed\n");
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
    string * block,
    uint8_t * bound,
    uint8_t * mes,
    uint8_t * pk,
    uint8_t * state
)
{
    CURL * curl;
    CURLcode res;

    curl = curl_easy_init();

    if (!curl)
    {
        return -1;
    }

    string str;
    InitString(&str);

    curl_easy_setopt(
        curl, CURLOPT_URL, "http://188.166.89.71:9052/mining/candidate"
    );
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        fprintf(
            stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res)
        );

        fflush(stdout);

        return 1;
    }
    else
    {
        ///printf("%s\n", str.ptr);

        fflush(stdout);
    }

    if (strcmp(block->ptr, str.ptr))
    {
        jsmn_parser parser;
        jsmntok_t tokens[7];

        jsmn_init(&parser);
        jsmn_parse(&parser, str.ptr, str.len, tokens, 7);

        HexStrToBigEndian(
            str.ptr + tokens[2].start, tokens[2].end - tokens[2].start,
            (uint8_t *)mes, NUM_SIZE_8
        );

        char tmp[65];

        DecStrToHexStrOf64(
            str.ptr + tokens[4].start, tokens[4].end - tokens[4].start, tmp
        );
        HexStrToLittleEndian(tmp, 64, bound, NUM_SIZE_8);

        HexStrToBigEndian(
            str.ptr + tokens[6].start, tokens[6].end - tokens[6].start,
            pk, PK_SIZE_8
        );

        // change state
        *state = 1;
    }
    else
    {
        // nothing changed
        *state = 0;
    }

    curl_easy_cleanup(curl);

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
    pos += PK_SIZE_8 << 1;

    strcpy(sol + pos, "\",\"n\":\"");
    pos += 7;

    BigEndianToHexStr(nonce, NONCE_SIZE_8, sol + pos);
    pos += NONCE_SIZE_8 << 1;

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

    string str;
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
            stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res)
        );

        fflush(stdout);
    }
    else
    {
        printf("%s\n", str.ptr);

        fflush(stdout);
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return 0;
}

// request.cu
