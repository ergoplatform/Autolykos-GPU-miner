#include "autolykos.h"
#include <cuda.h>
#include <curand.h>

// Little-endian byte access
#ifndef B2B_GET64
#define B2B_GET64(p)                            \
    (((uint64_t) ((uint8_t *) (p))[0]) ^        \
    (((uint64_t) ((uint8_t *) (p))[1]) << 8) ^  \
    (((uint64_t) ((uint8_t *) (p))[2]) << 16) ^ \
    (((uint64_t) ((uint8_t *) (p))[3]) << 24) ^ \
    (((uint64_t) ((uint8_t *) (p))[4]) << 32) ^ \
    (((uint64_t) ((uint8_t *) (p))[5]) << 40) ^ \
    (((uint64_t) ((uint8_t *) (p))[6]) << 48) ^ \
    (((uint64_t) ((uint8_t *) (p))[7]) << 56))
#endif

// Cyclic right rotation
#ifndef ROTR64
#define ROTR64(x, y)  (((x) >> (y)) ^ ((x) << (64 - (y))))
#endif

// G mixing function
#ifndef B2B_G
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
#endif

////////////////////////////////////////////////////////////////////////////////
//  Hash message
////////////////////////////////////////////////////////////////////////////////
void partialHash(
    // context
    blake2b_ctx * ctx,
    // optional secret key
    const void * key,
    // message
    const void * mes,
    // message length in bytes
    uint32_t meslen
) {
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

    int i;
    int j;

    uint64_t v[16];
    uint64_t m[16];

    //====================================================================//
    //  Initialize context
    //====================================================================//
    for (j = 0; j < 8; ++j)
    {
        ctx->h[j] = blake2b_iv[j];
    }

    ctx->h[0] ^= 0x01010000 ^ (KEY_LEN << 8) ^ HASH_LEN;

    ctx->t[0] = 0;
    ctx->t[1] = 0;
    ctx->c = 0;

    for (j = KEY_LEN; j < 128; ++j)
    {
        ctx->b[j] = 0;
    }

    //====================================================================//
    //  Hash key [optional]
    //====================================================================//
    for (j = 0; j < KEY_LEN; ++j)
    {
        if (ctx->c == 128)
        {
            ctx->t[0] += ctx->c;
            ctx->t[1] += (ctx->t[0] < ctx->c)? 1: 0;

            for (i = 0; i < 8; ++i)
            {
                v[i] = ctx->h[i];
                v[i + 8] = blake2b_iv[i];
            }

            v[12] ^= ctx->t[0];
            v[13] ^= ctx->t[1];

            for (i = 0; i < 16; i++)
            {
                m[i] = B2B_GET64(&ctx->b[8 * i]);
            }

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

            for (i = 0; i < 8; ++i)
            {
                ctx->h[i] ^= v[i] ^ v[i + 8];
            }

            ctx->c = 0;
        }

        ctx->b[ctx->c++] = ((const uint8_t *)key)[j];
    }

    if (KEY_LEN > 0)
    {
        ctx->c = 128;
    }

    //====================================================================//
    //  Hash message
    //====================================================================//
    for (j = 0; j < meslen; ++j)
    {
        if (ctx->c == 128)
        {
            ctx->t[0] += ctx->c;
            ctx->t[1] += (ctx->t[0] < ctx->c)? 1: 0;

            for (i = 0; i < 8; ++i)
            {
                v[i] = ctx->h[i];
                v[i + 8] = blake2b_iv[i];
            }

            v[12] ^= ctx->t[0];
            v[13] ^= ctx->t[1];

            for (i = 0; i < 16; i++)
            {
                m[i] = B2B_GET64(&ctx->b[8 * i]);
            }

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

            for (i = 0; i < 8; ++i)
            {
                ctx->h[i] ^= v[i] ^ v[i + 8];
            }

            ctx->c = 0;
        }

        ctx->b[ctx->c++] = ((const uint8_t *)mes)[j];
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Block mining                                                               
////////////////////////////////////////////////////////////////////////////////
__global__ void blockMining(
    const uint32_t * data,
    // pregenerated nonces
    const void * non,
    // precalculated hashes
    const void * hash,
    // results
    uint32_t * res
) {
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

    // local
    uint64_t v[16];
    uint64_t m[16];
    uint32_t ind[K_SIZE];
    // 5 * 64 bits, if HASH_LEN == 32
    uint8_t h[HASH_LEN + 4];

    uint32_t j;
    uint32_t tid = threadIdx.x;
    __shared__ uint32_t shm[64];

    shm[tid] = data[tid];
    __syncthreads();

    // shared
    uint32_t * key = (uint32_t *)shm;
    blake2b_ctx * ctx;

#pragma unroll
    for (int l = 0; l < H_SIZE; ++l) 
    {
        ctx = (blake2b_ctx *)(shm + 8);

        tid = (
            threadIdx.x + blockDim.x * blockIdx.x + l * gridDim.x * blockDim.x
        ) << 3;

        const uint8_t * mes = (const uint8_t *)((const uint32_t *)non + tid);

    //====================================================================//
    //  Hash nonce
    //====================================================================//
        for (j = 0; ctx->c < 128 && j < NON_LEN; ++j)
        {
            ctx->b[ctx->c++] = mes[j];
        }

        while (j < NON_LEN)
        {
            ctx->t[0] += ctx->c;
            ctx->t[1] += 1 - !(ctx->t[0] < ctx->c);

#pragma unroll
            for (int i = 0; i < 8; ++i)
            {
                v[i] = ctx->h[i];
                v[i + 8] = blake2b_iv[i];
            }

            v[12] ^= ctx->t[0];
            v[13] ^= ctx->t[1];

#pragma unroll
            for (int i = 0; i < 16; i++)
            {
                m[i] = B2B_GET64(&ctx->b[8 * i]);
            }

#pragma unroll
            for (int i = 0; i < 12; ++i)
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
            for (int i = 0; i < 8; ++i)
            {
                ctx->h[i] ^= v[i] ^ v[i + 8];
            }

            ctx->c = 0;
           
            while (ctx->c < 128 && j < NON_LEN)
            {
                ctx->b[ctx->c++] = mes[j++];
            }
        }

    //====================================================================//
    //  Finalize h
    //====================================================================//
        ctx->t[0] += ctx->c;
        ctx->t[1] += 1 - !(ctx->t[0] < ctx->c);

        while (ctx->c < 128)
        {
            ctx->b[ctx->c++] = 0;
        }

#pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            v[i] = ctx->h[i];
            v[i + 8] = blake2b_iv[i];
        }

        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[1];
        v[14] = ~v[14];

#pragma unroll
        for (int i = 0; i < 16; i++)
        {
            m[i] = B2B_GET64(&ctx->b[8 * i]);
        }

#pragma unroll
        for (int i = 0; i < 12; ++i)
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
        for (int i = 0; i < 8; ++i)
        {
            ctx->h[i] ^= v[i] ^ v[i + 8];
        }

        for (j = 0; j < HASH_LEN; ++j)
        {
            h[j] = (ctx->h[j >> 3] >> ((j & 7) << 3)) & 0xFF;
        }

    //===================================================================//
    //  Generate indices
    //===================================================================//
#pragma unroll
        for (int i = 0; i < 3; ++i)
        {
            h[HASH_LEN + i] = h[i];
        }

#pragma unroll
        for (int i = 0; i < K_SIZE; ++i)
        {
            ind[i] = *((uint32_t *)(h + i)) & 0x03FFFFFF;
        }
        
    //===================================================================//
    //  Calculate result
    //===================================================================//
        uint32_t * r = (uint32_t *)h;

        // first addition of hashes -> r
        asm volatile (
            "add.cc.u32 %0, %1, %2;":
            "=r"(h[0]): "r"(hash[ind[0]][0]), "r"(hash[ind[1]][0])
        );

#pragma unroll
        for (int i = 1; i < 8; ++i)
        {
            asm volatile (
                "addc.cc.u32 %0, %1, %2;":
                "=r"(h[i]): "r"(hash[ind[0]][i]), "r"(hash[ind[1]][i])
            );
        }

        asm volatile (
            "addc.u32 %0, 0, 0;": "=r"(r[8])
        );

        // remaining additions
#pragma unroll
        for (int k = 2; k < K_SIZE; ++k)
        {
            asm volatile (
                "add.cc.u32 %0, %0, %1;": "+r"(r[0]): "r"(hash[ind[k]][0])
            );

#pragma unroll
            for (int i = 1; i < 8; ++i)
            {
                asm volatile (
                    "addc.cc.u32 %0, %0, %1;": "+r"(r[i]): "r"(hash[ind[k]][i])
                );
            }

            asm volatile (
                "addc.u32 %0, %0, 0;": "+r"(r[8])
            );
        }

        // subtraction of secret key
        asm volatile (
            "sub.cc.u32 %0, %0, %1;": "+r"(r[0]): "r"(key[0])
        );

#pragma unroll
        for (int i = 1; i < 8; ++i)
        {
            asm volatile (
                "subc.cc.u32 %0, %0, %1;": "+r"(r[i]): "r"(key[i])
            );
        }

        asm volatile (
            "subc.u32 %0, %0, 0;": "+r"(r[8])
        );


    //===================================================================//
    //  result mod q
    //===================================================================//
        uint32_t * med = ind;
        uint32_t * d = ind + 5; 
        uint32_t * carry = ind + 6;

        *d = (r[8] << 4) | (r[7] >> 28);

        // correct highest 32 bits
        r[7] &= 0x0FFFFFFF;

    //====================================================================//
        asm volatile (
            "mul.lo.u32 %0, %1, "q0_s";": "=r"(med[0]): "r"(*d)
        );
        asm volatile (
            "mul.hi.u32 %0, %1, "q0_s";": "=r"(med[1]): "r"(*d)
        );
        asm volatile (
            "mul.lo.u32 %0, %1, "q2_s";": "=r"(med[2]): "r"(*d)
        );
        asm volatile (
            "mul.hi.u32 %0, %1, "q2_s";": "=r"(med[3]): "r"(*d)
        );

        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q1_s", %0;": "+r"(med[1]): "r"(*d)
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, "q1_s", %0;": "+r"(med[2]): "r"(*d)
        );
        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;": "+r"(med[3]): "r"(*d)
        );
        asm volatile (
            "madc.hi.u32 %0, %1, "q3_s", 0;": "=r"(med[4]): "r"(*d)
        );

    //====================================================================//
        asm volatile (
            "sub.cc.u32 %0, %0, %1;": "+r"(r[0]): "r"(med[0])
        );

#pragma unroll
        for (int i = 1; i < 5; ++i)
        {
            asm volatile (
                "subc.cc.u32 %0, %0, %1;": "+r"(r[i]): "r"(med[i])
            );
        }

#pragma unroll
        for (int i = 5; i < 8; ++i)
        {
            asm volatile (
                "subc.cc.u32 %0, %0, 0;": "+r"(r[i])
            );
        }

    //====================================================================//
        asm volatile (
            "subc.u32 %0, 0, 0;": "=r"(*carry)
        );

        *carry = 0 - *carry;

        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q0_s", %0;": "+r"(r[0]): "r"(*carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q1_s", %0;": "+r"(r[1]): "r"(*carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q2_s", %0;": "+r"(r[2]): "r"(*carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;": "+r"(r[3]): "r"(*carry)
        );

#pragma unroll
        for (int i = 0; i < 3; ++i)
        {
            asm volatile (
                "addc.cc.u32 %0, %0, 0;": "+r"(r[i + 4])
            );
        }

        asm volatile (
            "addc.u32 %0, %0, 0;": "+r"(r[7])
        );

    //===================================================================//
    //  dump result to global memory
    //===================================================================//
#pragma unroll
        for (int i = 0; i < 3; ++i)
        {
            res[tid + i] = r[i];
        }
    }

    return;
}
