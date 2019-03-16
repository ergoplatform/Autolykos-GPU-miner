#include "jsmn/jsmn.h"
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

struct string
{
    char * ptr;
    size_t len;
};

void init_string(
    string * str
) {
    str->len = 0;
    str->ptr = (char *)malloc(str->len + 1);

    if (str->ptr == NULL)
    {
        fprintf(stderr, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }

    str->ptr[0] = '\0';
}

size_t writefunc(
    void * ptr, size_t size, size_t nmemb, struct string * str
) {
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
void convertDecToHex(
    char * in,
    uint8_t inlen,
    char * out
) {
    uint32_t fs[inlen];
    uint32_t tmp;
    uint32_t rem;
    uint32_t ip;

    for (int i = inlen - 1, k = 0; i >= 0; --i)
    {
        if (in[i] >= '0' && in[i] <= '9')
        {
            fs[k++] = (uint32_t)(in[i] - '0');
        }
        else
        {
            printf("ERROR\n");
        }
    }

    uint32_t ts[74] = {1};
    uint32_t accs[74] = {0};

    for (int i = 0; i < inlen; ++i)
    {
        for (int j = 0; j < 64; ++j)
        {
            accs[j] += ts[j] * fs[i];

            tmp = accs[j];
            rem = 0;
            ip = j;

            do
            {
                rem = tmp >> 4;
                accs[ip++] = tmp - (rem << 4);
                accs[ip] += rem;
                tmp = accs[ip];
            }
            while (tmp >= 16);
        }

        for (int j = 0; j < 64; ++j)
        {
            ts[j] *= 10;
        }

        for (int j = 0; j < 64; ++j)
        {
            tmp = ts[j];
            rem = 0;
            ip = j;

            do
            {
                rem = tmp >> 4;
                ts[ip++] = tmp - (rem << 4);
                ts[ip] += rem;
                tmp = ts[ip];
            }
            while (tmp >= 16);
        }
    }

    for (int i = 63; i >= 0; --i)
    {
        out[63 - i]
            = (accs[i] < 10)? (char)(accs[i] + '0'): (char)(accs[i] + 'A' - 10);
    }

    out[64] = '\0';

    return;
}

#ifndef REVERSE_ENDIAN
#define REVERSE_ENDIAN(p)                                                      \
    ((((uint64_t)((uint8_t *)(p))[0]) << 56) ^                                 \
    (((uint64_t)((uint8_t *)(p))[1]) << 48) ^                                  \
    (((uint64_t)((uint8_t *)(p))[2]) << 40) ^                                  \
    (((uint64_t)((uint8_t *)(p))[3]) << 32) ^                                  \
    (((uint64_t)((uint8_t *)(p))[4]) << 24) ^                                  \
    (((uint64_t)((uint8_t *)(p))[5]) << 16) ^                                  \
    (((uint64_t)((uint8_t *)(p))[6]) << 8) ^                                   \
    ((uint64_t)((uint8_t *)(p))[7]))
#endif

#ifndef INPLACE_REVERSE_ENDIAN
#define INPLACE_REVERSE_ENDIAN(p)                                              \
{                                                                              \
    *((uint64_t *)(p))                                                         \
    = ((((uint64_t)((uint8_t *)(p))[0]) << 56) ^                               \
    (((uint64_t)((uint8_t *)(p))[1]) << 48) ^                                  \
    (((uint64_t)((uint8_t *)(p))[2]) << 40) ^                                  \
    (((uint64_t)((uint8_t *)(p))[3]) << 32) ^                                  \
    (((uint64_t)((uint8_t *)(p))[4]) << 24) ^                                  \
    (((uint64_t)((uint8_t *)(p))[5]) << 16) ^                                  \
    (((uint64_t)((uint8_t *)(p))[6]) << 8) ^                                   \
    ((uint64_t)((uint8_t *)(p))[7]));                                          \
}
#endif

void scanToBigEndian(
    const char * in,
    const int inlen,
    uint8_t * out,
    // in bytes
    const int outlen
)
{
    memset(out, 0, outlen);

    for (int i = (outlen << 1) - inlen; i < (outlen << 1); ++i)
    {
        out[i >> 1]
            |= ((
                (in[i] >= 'A')?
                in[i] - 'A' + 0xA: 
                in[i] - '0' 
            ) & 0xF) << ((!(i & 1)) << 2);
    }

    return;
}

void scanToLittleEndian(
    const char * in,
    const int inlen,
    uint8_t * out,
    // in bytes
    const int outlen
)
{
    memset(out, 0, outlen);

    for (int i = 0; i < inlen; ++i)
    {
        out[i >> 1]
            |= ((
                (in[inlen - i - 1] >= 'A')?
                in[inlen - i - 1] - 'A' + 0xA: 
                in[inlen - i - 1] - '0' 
            ) & 0xF) << (((i & 1)) << 2);
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
int main(
    void
) {
    CURL * curl;
    CURLcode res;

    curl = curl_easy_init();

    if (curl)
    {
        string s;
        init_string(&s);

        curl_easy_setopt(
            curl, CURLOPT_URL, "http://188.166.89.71:9052/mining/candidate"
        );
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

        res = curl_easy_perform(curl);

        ///printf("%s\n", s.ptr);
        jsmn_parser parser;
        jsmntok_t tokens[7];

        jsmn_init(&parser);
        jsmn_parse(&parser, s.ptr, s.len, tokens, 7);

        int i;

        char hs[65];
        for (i = 0; i < 7; ++i)
        {
            ///printf(
            ///    "%d, [%d, %d], %d\n",
            ///    tokens[i].type, tokens[i].start, tokens[i].end, tokens[i].size
            ///);

            ///sprintf(s.ptr, "%"%d"s", tokens[i].end - tokens[i].start);
            if (i && !(i & 1))
            {
                if (i != 4)
                {
                    printf(
                        "%.*s\n",
                        tokens[i].end - tokens[i].start, s.ptr + tokens[i].start
                    );
                }
            }

            if (i == 4)
            {
                convertDecToHex(s.ptr + tokens[i].start, tokens[i].end - tokens[i].start, hs);

                printf(
                    "%64s\n",
                    hs
                );
                ///printf(
                ///    "0000C3AC56F4E254AB64A87AA76F21D03F01D698ACE1D3B62232A7CCAA369909\n"
                ///);
            }
        }

        uint64_t mes[4];
        uint64_t b[4];
        uint8_t pk[33];

///    SCAN_TO_BIG_ENDIAN(mes);
///    SCAN_TO_LITTLE_ENDIAN(bound);
//
///    status = fscanf(in, "%"SCNx8"\n", (uint8_t *)pk);
///    SCAN_TO_BIG_ENDIAN((uint8_t *)pk + 1);

        scanToBigEndian(
            s.ptr + tokens[2].start, tokens[2].end - tokens[2].start, (uint8_t *)mes, 32
        );

        printf(
            "m = 0x%016lX %016lX %016lX %016lX\n",
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)mes)) + 0),
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)mes)) + 1),
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)mes)) + 2),
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)mes)) + 3)
        );

        scanToLittleEndian(hs, 64, (uint8_t *)b, 32);

        printf(
            "b = 0x%016lX %016lX %016lX %016lX\n",
            ((uint64_t *)b)[3], ((uint64_t *)b)[2],
            ((uint64_t *)b)[1], ((uint64_t *)b)[0]
        );

        scanToBigEndian(
            s.ptr + tokens[6].start, tokens[6].end - tokens[6].start, pk, 33
        );

        printf(
            "pk = 0x%02lX %016lX %016lX %016lX %016lX\n",
            pk[0],
            REVERSE_ENDIAN(((uint64_t *)(pk + 1) + 0)),
            REVERSE_ENDIAN(((uint64_t *)(pk + 1) + 1)),
            REVERSE_ENDIAN(((uint64_t *)(pk + 1) + 2)),
            REVERSE_ENDIAN(((uint64_t *)(pk + 1) + 3))
        );

        ////printf("\n");
        fflush(stdout);

        free(s.ptr);

        curl_easy_cleanup(curl);
    }

    return 0;
}
