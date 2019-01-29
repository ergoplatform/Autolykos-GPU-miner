#include "blake2b.h"

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
    uint32_t outlen,
    const void * key,
    uint32_t keylen,
    const void * in,
    uint32_t inlen
) {
    int k;

    const uint64_t blake2b_iv[8] = {
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
    };

    const uint8_t sigma[12][16] = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
    };

    //====================================================================//
#pragma unroll
    for (k = 0; k < 8; ++k)
    {
        ctx->h[k] = blake2b_iv[k];
    }

    ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

    ctx->t[0] = 0;
    ctx->t[1] = 0;
    ctx->c = 0;
    ctx->outlen = outlen;

#pragma unroll
    for (k = keylen; k < 128; ++k)
    {
        ctx->b[k] = 0;
    }

    //====================================================================//
    int i;
    uint64_t v[16];
    uint64_t m[16];

    for (k = 0; k < keylen & 0xFFFFFF80; ++k)
    {
        while (ctx->c < 128)
        {
            ctx->b[ctx->c++] = ((const uint8_t *)key)[k++];
        }

        ctx->t[0] += ctx->c;
        ctx->t[1] += 1 - !(ctx->t[0] < ctx->c);

#pragma unroll
        for (i = 0; i < 8; ++i)
        {
            v[i] = ctx->h[i];
            v[i + 8] = blake2b_iv[i];
        }

        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[1];

#pragma unroll
        for (i = 0; i < 16; i++)
        {
            m[i] = B2B_GET64(&ctx->b[8 * i]);
        }

#pragma unroll
        for (i = 0; i < 12; ++i)
        {
            B2B_G(0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
            B2B_G(1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
            B2B_G(2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
            B2B_G(3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
            B2B_G(0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
            B2B_G(1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
            B2B_G(2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
            B2B_G(3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
        }

#pragma unroll
        for (i = 0; i < 8; ++i)
        {
            ctx->h[i] ^= v[i] ^ v[i + 8];
        }

        ctx->c = 0;

        ctx->b[ctx->c++] = ((const uint8_t *)key)[k];
    }

    while (k < keylen)
    {
        ctx->b[ctx->c++] = ((const uint8_t *)key)[k++];
    }

    //ctx->c = (keylen > 0)? 128: ctx->c;
    ctx->c = ((1 - !(keylen > 0)) << 7) + (!(keylen > 0)) * ctx->c;

    //====================================================================//
    for (k = 0; ctx->c < 128 && k < inlen; ++k)
    {
        ctx->b[ctx->c++] = ((const uint8_t *)in)[k];
    }

    while (k < inlen)
    {
        ctx->t[0] += ctx->c;
        ctx->t[1] += 1 - !(ctx->t[0] < ctx->c);

#pragma unroll
        for (i = 0; i < 8; ++i)
        {
            v[i] = ctx->h[i];
            v[i + 8] = blake2b_iv[i];
        }

        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[1];

#pragma unroll
        for (i = 0; i < 16; i++)
        {
            m[i] = B2B_GET64(&ctx->b[8 * i]);
        }

#pragma unroll
        for (i = 0; i < 12; ++i)
        {
            B2B_G(0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
            B2B_G(1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
            B2B_G(2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
            B2B_G(3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
            B2B_G(0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
            B2B_G(1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
            B2B_G(2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
            B2B_G(3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
        }

#pragma unroll
        for (i = 0; i < 8; ++i)
        {
            ctx->h[i] ^= v[i] ^ v[i + 8];
        }

        ctx->c = 0;
       
        while (ctx->c < 128 && k < inlen)
        {
            ctx->b[ctx->c++] = ((const uint8_t *)in)[k++];
        }
    }

    //====================================================================//
    ctx->t[0] += ctx->c;
    ctx->t[1] += 1 - !(ctx->t[0] < ctx->c);

    while (ctx->c < 128)
    {
        ctx->b[ctx->c++] = 0;
    }

#pragma unroll
    for (i = 0; i < 8; ++i)
    {
        v[i] = ctx->h[i];
        v[i + 8] = blake2b_iv[i];
    }

    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    v[14] = ~v[14];

#pragma unroll
    for (i = 0; i < 16; i++)
    {
        m[i] = B2B_GET64(&ctx->b[8 * i]);
    }

#pragma unroll
    for (i = 0; i < 12; ++i)
    {
        B2B_G(0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
        B2B_G(1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
        B2B_G(2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
        B2B_G(3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
        B2B_G(0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
        B2B_G(1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
        B2B_G(2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
        B2B_G(3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
    }

#pragma unroll
    for (i = 0; i < 8; ++i)
    {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }

    for (k = 0; k < ctx->outlen; ++k)
    {
        ((uint8_t *)out)[k] = (ctx->h[k >> 3] >> ((k & 7) << 3)) & 0xFF;
    }

    return;
}
