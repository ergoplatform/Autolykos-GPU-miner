// conversion.cc

/*******************************************************************************

    CONVERSION -- Big integers format conversion

*******************************************************************************/

#include "../include/conversion.h"
#include "../include/definitions.h"
#include "../include/easylogging++.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

////////////////////////////////////////////////////////////////////////////////
//  Convert string of decimal digits to string of 64 hexadecimal digits
////////////////////////////////////////////////////////////////////////////////
int DecStrToHexStrOf64(
    const char * in,
    const uint32_t inlen,
    char * out
) {
    //somehow MSVC does not accept array with const size
    #ifndef _WIN32
    uint32_t fs[inlen];
    #else
    uint32_t fs[1024];
    #endif
    uint32_t tmp;
    uint32_t rem;
    uint32_t ip;

    for (int i = inlen - 1, k = 0; i >= 0; --i)
    {
        if (in[i] >= '0' && in[i] <= '9') { fs[k++] = (uint32_t)(in[i] - '0'); }
        else
        { 
            char errbuf[1024];

            errbuf[0] = '\0';
            strncat(errbuf, in, inlen);

            LOG(ERROR) << "DecStrToHexStrOf64 failed on string " << errbuf;
            CALL(0, ERROR_IO); 
        }
    }

    uint32_t ts[74] = {1};
    uint32_t accs[74] = {0};

    for (uint_t i = 0; i < inlen; ++i)
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

        for (int j = 0; j < 64; ++j) { ts[j] *= 10; }

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

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//  Convert string of hexadecimal digits to big endian
////////////////////////////////////////////////////////////////////////////////
void HexStrToBigEndian(
    const char * in,
    const uint32_t inlen,
    uint8_t * out,
    const uint32_t outlen
)
{
    memset(out, 0, outlen);

    for (uint_t i = (outlen << 1) - inlen; i < (outlen << 1); ++i)
    {
        out[i >> 1]
            |= (((in[i] >= 'A')?  in[i] - 'A' + 0xA: in[i] - '0') & 0xF)
            << ((!(i & 1)) << 2);
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Convert string of hexadecimal digits to little endian
////////////////////////////////////////////////////////////////////////////////
void HexStrToLittleEndian(
    const char * in,
    const uint32_t inlen,
    uint8_t * out,
    const uint32_t outlen
)
{
    memset(out, 0, outlen);

    for (uint_t i = 0; i < inlen; ++i)
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
//  Convert little endian of 256 bits to string of decimal digits
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

        for (int j = 0; j < 78; ++j) { ts[j] <<= 4; }

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
            if (!(accs[i])) { continue; }
            else { lead = 0; }
        }

        out[k++] = (char)(accs[i] + '0');
    }

    out[k] = '\0';
    *outlen = k;

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Convert little endian to string of hexadecimal digits
////////////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////////////
//  Convert big endian to string of hexadecimal digits
////////////////////////////////////////////////////////////////////////////////
void BigEndianToHexStr(
    const uint8_t * in,
    const uint32_t inlen,
    char * out
)
{
    uint8_t dig;

    for (uint_t i = 0; i < inlen << 1; ++i)
    {
        dig = (uint8_t)(in[i >> 1] >> (!(i & 1) << 2)) & 0xF;
        out[i] = (dig <= 9)? (char)dig + '0': (char)dig + 'A' - 0xA;
    }

    out[inlen << 1] = '\0';

    return;
}

// conversion.cc
