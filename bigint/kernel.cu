#include "blake2b.h"

// 4 bytes
#define q3 = 0x14def9de
// 4 bytes
#define q2 = 0xa2f79cd6
// 4 bytes
#define q1 = 0x5812631a
// 4 bytes
#define q0 = 0x5cf5d3ed

// Cyclic right rotation.
#ifndef ROTR64
#define ROTR64(x, y)  (((x) >> (y)) ^ ((x) << (64 - (y))))
#endif

// Little-endian byte access.
#define B2B_GET64(p)                            \
    (((uint64_t) ((uint8_t *) (p))[0]) ^        \
    (((uint64_t) ((uint8_t *) (p))[1]) << 8) ^  \
    (((uint64_t) ((uint8_t *) (p))[2]) << 16) ^ \
    (((uint64_t) ((uint8_t *) (p))[3]) << 24) ^ \
    (((uint64_t) ((uint8_t *) (p))[4]) << 32) ^ \
    (((uint64_t) ((uint8_t *) (p))[5]) << 40) ^ \
    (((uint64_t) ((uint8_t *) (p))[6]) << 48) ^ \
    (((uint64_t) ((uint8_t *) (p))[7]) << 56))

// G Mixing function.
#define B2B_G(a, b, c, d, x, y)     \
{                                   \
    v[a] = v[a] + v[b] + x;         \
    v[d] = ROTR64(v[d] ^ v[a], 32); \
    v[c] = v[c] + v[d];             \
    v[b] = ROTR64(v[b] ^ v[c], 24); \
    v[a] = v[a] + v[b] + y;         \
    v[d] = ROTR64(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d];             \
    v[b] = ROTR64(v[b] ^ v[c], 63); \
}
////////////////////////////////////////////////////////////////////////////////
// Hash
////////////////////////////////////////////////////////////////////////////////
__global__ void blake2b(
    blake2b_ctx * ctx,
    void * out,
    size_t outlen,
    const void * key,
    size_t keylen,
    const void * in,
    size_t inlen
) {
    // q == [0x10000000, 0, 0, 0, q3, q2, q1, q0]   32
    // q == [0x1000000000000000, 0, Q1, Q0]         64
    int i;
    uint64_t d1;
    uint32_t med[6];

    for (int i = 4; i > 0; --i)
    {
        d1 = ((x[i] << 4) | (x[i - 1] >> 60)) - (x[i] >> 60);

        asm volatile (
            "mul.lo.cc.u32 %0, %1, q0;":
            "=r"(med[0]):
            "r"(((uint32_t *)&d1)[0])
        );
        asm volatile (
            "mulc.hi.cc.u32 %0, %1, q0;":
            "=r"(med[1]):
            "r"(((uint32_t *)&d1)[0])
        );
        asm volatile (
            "mul.lo.cc.u32 %0, %1, q2;":
            "=r"(med[2]):
            "r"(((uint32_t *)&d1)[0])
        );
        asm volatile (
            "mulc.hi.cc.u32 %0, %1, q2;":
            "=r"(med[3]):
            "r"(((uint32_t *)&d1)[0])
        );
        asm volatile (
            "addc.u32 %0, 0, 0;":
            "=r"(med[4])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, q1, %0;":
            "+r"(med[1]):
            "r"(((uint32_t *)&d1)[0])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, q1, %0;":
            "+r"(med[2]):
            "r"(((uint32_t *)&d1)[0])
        );
        asm volatile (
            "mad.lo.cc.u32 %0, %1, q3, %0;":
            "+r"(med[3]):
            "r"(((uint32_t *)&d1)[0])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, q3, %0;":
            "+r"(med[4]):
            "r"(((uint32_t *)&d1)[0])
        );
        asm volatile (
            "addc.u32 %0, 0, 0;":
            "=r"(med[5])
        );

    //====================================================================//

        //(d1[0] * p[0]).lo
        //(d1[0] * p[0]).hi
        //(d1[0] * p[2]).lo
        //(d1[0] * p[2]).hi
        //Потом один addc нуля к пятому слову.
        (d1[0] * p[1]).lo
        (d1[0] * p[1]).hi
        (d1[0] * p[3]).lo
        (d1[0] * p[3]).hi
        Потом один addc нуля к шестому слову.
        (d1[1] * p[0]).lo
        (d1[1] * p[0]).hi
        (d1[1] * p[2]).lo
        (d1[1] * p[2]).hi
        Один addc нуля к шестому слову.
        (d1[1] * p[1]).lo
        (d1[1] * p[1]).hi
        (d1[1] * p[3]).lo
        (d1[1] * p[3]).hi
    }
        

    asm("sub.cc.u32 %0, %1, %2;" : "=r"(i) : "r"(j), "r"(k));

    return;
}
