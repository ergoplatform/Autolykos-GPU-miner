#include "jsmn/jsmn.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <curl/curl.h>

////////////////////////////////////////////////////////////////////////////////
struct string
{
    char * ptr;
    size_t len;
};

void InitString(
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

size_t WriteFunc(
    void * ptr,
    size_t size,
    size_t nmemb,
    string * str
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
void DecStrToHexStrOf64(
    const char * in,
    const uint32_t inlen,
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
            = (accs[i] < 10)?
            (char)(accs[i] + '0'):
            (char)(accs[i] + 'A' - 0xA);
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

void HexStrToBigEndian(
    const char * in,
    const uint32_t inlen,
    uint8_t * out,
    const uint32_t outlen
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

void HexStrToLittleEndian(
    const char * in,
    const uint32_t inlen,
    uint8_t * out,
    const uint32_t outlen
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
void LittleEndianOf256ToDecStr(
    const uint8_t * in,
    char * out,
    uint32_t * outlen
) {
    uint32_t fs[64];
    uint32_t tmp;
    uint32_t rem;
    uint32_t ip;

    for (int i = 0; i < 64; ++i)
    {
        fs[i] = (uint32_t)(in[i >> 1] >> (((i & 1)) << 2)) & 0xF;
    }

    uint32_t ts[90] = {1};
    uint32_t accs[90] = {0};

    for (int i = 0; i < 64; ++i)
    {
        for (int j = 0; j < 78; ++j)
        {
            accs[j] += ts[j] * fs[i];

            tmp = accs[j];
            rem = 0;
            ip = j;

            do
            {
                rem = tmp / 10;
                accs[ip++] = tmp - rem * 10;
                accs[ip] += rem;
                tmp = accs[ip];
            }
            while (tmp >= 10);
        }

        for (int j = 0; j < 78; ++j)
        {
            ts[j] <<= 4;
        }

        for (int j = 0; j < 78; ++j)
        {
            tmp = ts[j];
            rem = 0;
            ip = j;

            do
            {
                rem = tmp / 10;
                ts[ip++] = tmp - rem * 10;
                ts[ip] += rem;
                tmp = ts[ip];
            }
            while (tmp >= 10);
        }
    }

    int k = 0;
    int lead = 1;

    for (int i = 77; i >= 0; --i)
    {
        if (lead)
        {
            if (!(accs[i]))
            {
                continue;
            }
            else
            {
                lead = 0;
            }
        }

        out[k++] = (char)(accs[i] + '0');
    }

    out[k] = '\0';
    *outlen = k;

    return;
}

void LittleEndianToHexStr(
    const uint8_t * in,
    const uint32_t inlen,
    char * out
)
{
    uint8_t dig;

    for (int i = (inlen << 1) - 1; i >= 0; --i)
    {
        dig = (uint8_t)(in[i >> 1] >> ((i & 1) << 2)) & 0xF;

        out[(inlen << 1) - i - 1]
            = (dig <= 9)? (char)dig + '0': (char)dig + 'A' - 0xA;
    }

    out[inlen << 1] = '\0';

    return;
}

void BigEndianToHexStr(
    const uint8_t * in,
    const uint32_t inlen,
    char * out
)
{
    uint8_t dig;

    for (int i = 0; i < inlen << 1; ++i)
    {
        dig = (uint8_t)(in[i >> 1] >> (!(i & 1) << 2)) & 0xF;

        out[i] = (dig <= 9)? (char)dig + '0': (char)dig + 'A' - 0xA;
    }

    out[inlen << 1] = '\0';

    return;
}

////////////////////////////////////////////////////////////////////////////////
int main(
    void
) {
    CURL * curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_ALL);
    
    curl = curl_easy_init();

    uint64_t mes[4];
    uint64_t b[4];
    uint64_t sk[4];
    uint8_t pk[33];
    char hs[65];

    if (curl)
    {
        string s;
        InitString(&s);

        curl_easy_setopt(
            curl, CURLOPT_URL, "http://188.166.89.71:9052/mining/candidate"
        );
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

        res = curl_easy_perform(curl);

        ///printf("%s\n", s.ptr);
        jsmn_parser parser;
        jsmntok_t tokens[9];

        jsmn_init(&parser);
        jsmn_parse(&parser, s.ptr, s.len, tokens, 9);

        for (int i = 0; i < 9; ++i)
        {
            if (i && !(i & 1))
            {
                if (i == 4)
                {
                    ///printf(
                    ///    "%.*s\n",
                    ///    tokens[i].end - tokens[i].start, s.ptr + tokens[i].start
                    ///);
                    DecStrToHexStrOf64(
                        s.ptr + tokens[i].start,
                        tokens[i].end - tokens[i].start, hs
                    );
                }
            }
        }

        HexStrToBigEndian(
            s.ptr + tokens[2].start, tokens[2].end - tokens[2].start,
            (uint8_t *)mes, 32
        );

        ///printf(
        ///    "m = 0x%016lX %016lX %016lX %016lX\n",
        ///    REVERSE_ENDIAN(((uint64_t *)((uint8_t *)mes)) + 0),
        ///    REVERSE_ENDIAN(((uint64_t *)((uint8_t *)mes)) + 1),
        ///    REVERSE_ENDIAN(((uint64_t *)((uint8_t *)mes)) + 2),
        ///    REVERSE_ENDIAN(((uint64_t *)((uint8_t *)mes)) + 3)
        ///);

        HexStrToLittleEndian(hs, 64, (uint8_t *)b, 32);

        ///char hhs[79];
        ///uint8_t hhslen;
        ///HexToDec((uint8_t *)b, 64, hhs, &hhslen);
        ///printf("\n%s\n", hhs);

        ///printf(
        ///    "b = 0x%016lX %016lX %016lX %016lX\n",
        ///    ((uint64_t *)b)[3], ((uint64_t *)b)[2],
        ///    ((uint64_t *)b)[1], ((uint64_t *)b)[0]
        ///);

        HexStrToLittleEndian(
            s.ptr + tokens[6].start, tokens[6].end - tokens[6].start,
            (uint8_t *)sk, 32
        );

        ///printf(
        ///    "sk = 0x%016lX %016lX %016lX %016lX\n",
        ///    ((uint64_t *)sk)[3], ((uint64_t *)sk)[2],
        ///    ((uint64_t *)sk)[1], ((uint64_t *)sk)[0]
        ///);

        HexStrToBigEndian(
            s.ptr + tokens[8].start, tokens[8].end - tokens[8].start, pk, 33
        );

        ///printf(
        ///    "pk = 0x%02lX %016lX %016lX %016lX %016lX\n",
        ///    pk[0],
        ///    REVERSE_ENDIAN(((uint64_t *)(pk + 1) + 0)),
        ///    REVERSE_ENDIAN(((uint64_t *)(pk + 1) + 1)),
        ///    REVERSE_ENDIAN(((uint64_t *)(pk + 1) + 2)),
        ///    REVERSE_ENDIAN(((uint64_t *)(pk + 1) + 3))
        ///);

        ////printf("\n");
        fflush(stdout);

        free(s.ptr);

        curl_easy_cleanup(curl);
    }

    char nonce[] = "0123456789ABCDEF";
    uint32_t curlen;
    uint32_t totlen = 6;

    char sol[256];

    strcpy(sol, "{\"w\":\"");
    BigEndianToHexStr((uint8_t *)pk, 33, sol + totlen);
    totlen += 33 << 1;
    strcpy(sol + totlen, "\",\"n\":\"");
    totlen += 7;
    strcpy(sol + totlen, nonce);
    totlen += 16;
    strcpy(sol + totlen, "\",\"d\":");
    totlen += 6;
    LittleEndianOf256ToDecStr((uint8_t *)b, sol + totlen, &curlen);
    totlen += curlen;
    strcpy(sol + totlen, "e0}\0");

    printf("%s\n", sol);

    CURL * curl_;

    curl_ = curl_easy_init();
    if (curl_)
    {
        string s_;
        InitString(&s_);

        curl_slist * headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(
            curl_, CURLOPT_URL, "http://188.166.89.71:9052/mining/solution"
        );

        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, sol);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s_);

        res = curl_easy_perform(curl_);

        if (res != CURLE_OK)
        {
            fprintf(
                stderr,
                "curl_easy_perform() failed: %s\n", curl_easy_strerror(res)
            );
        } 
        else
        {
            printf("%s\n", s_.ptr);
        }

        curl_easy_cleanup(curl_);
        curl_slist_free_all(headers);
    }

    curl_global_cleanup();

    return 0;
}
