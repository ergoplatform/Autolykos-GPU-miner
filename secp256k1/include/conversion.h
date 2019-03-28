#ifndef CONVERSION_H
#define CONVERSION_H

/*******************************************************************************

    CONVERSION -- Big integers format conversion

*******************************************************************************/

#include <stdint.h>

// convert string of decimal digits to string of 64 hexadecimal digits
int DecStrToHexStrOf64(
    const char * in,
    const uint32_t inlen,
    char * out
);

// convert string of hexadecimal digits to big endian
void HexStrToBigEndian(
    const char * in,
    const uint32_t inlen,
    uint8_t * out,
    const uint32_t outlen
);

// convert string of hexadecimal digits to little endian
void HexStrToLittleEndian(
    const char * in,
    const uint32_t inlen,
    uint8_t * out,
    const uint32_t outlen
);

// convert little endian of 256 bits to string of decimal digits
void LittleEndianOf256ToDecStr(
    const uint8_t * in,
    char * out,
    uint32_t * outlen
);

// convert little endian to string of hexadecimal digits
void LittleEndianToHexStr(
    const uint8_t * in,
    const uint32_t inlen,
    char * out
);

// convert big endian to string of hexadecimal digits
void BigEndianToHexStr(
    const uint8_t * in,
    const uint32_t inlen,
    char * out
);

#endif // CONVERSION_H
