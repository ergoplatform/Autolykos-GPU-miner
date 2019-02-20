#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

////////////////////////////////////////////////////////////////////////////////
//  Constants
////////////////////////////////////////////////////////////////////////////////
// keys and hashes size
#define NUM_SIZE_8    32
#define NUM_SIZE_32   (NUM_SIZE_8 >> 2)

// nonce size
#define NONCE_SIZE_8  8
#define NONCE_SIZE_32 (NONCE_SIZE_8 >> 2)

// number of indices
#define K_LEN         32

// number of precalculated hashes
#define N_LEN         0x4000000          // 2^26

// mod 2^26 mask
#define N_MASK        0x03FFFFFF

// boundary for puzzle
//                      8765432187654321
#define B3            0x0000000003FFFFFF
#define B2            0xFFFFFFFFFFFFFFFF
#define B1            0xFFFFFFFFFFFFFFFF
#define B0            0xFFFFFFFFFFFFFFFF

////////////////////////////////////////////////////////////////////////////////
// number of hashes per thread
#define H_LEN         1                  

// total number of hash loads (threads) per iteration
#define L_LEN         (0x400000 / H_LEN) // 2^22

// mining kernel block size 
#define B_DIM         64              

////////////////////////////////////////////////////////////////////////////////
// 64 bits
#define Q1            0x14DEF9DEA2F79CD6
#define Q0            0x5812631A5CF5D3ED

// 32 bits
#define q3_s          "0x14DEF9DE"
#define q2_s          "0xA2F79CD6"
#define q1_s          "0x5812631A"
#define q0_s          "0x5CF5D3ED"

////////////////////////////////////////////////////////////////////////////////
// 0xF * Q -- multiplier-of-Q floor of 2^256
#define FQ3           0xF000000000000000
#define FQ2           1
#define FQ1           0x3910A40B8C82308F
#define FQ0           0x2913CE8B72676AE3

////////////////////////////////////////////////////////////////////////////////
// hash state context
typedef struct {
    // input buffer
    uint8_t b[128];
    // chained state
    uint64_t h[8];
    // total number of bytes
    uint64_t t[2];
    // counter for b
    uint32_t c;
} blake2b_ctx;

////////////////////////////////////////////////////////////////////////////////
// initialization vector
#ifndef B2B_IV
#define B2B_IV(v)                              \
{                                              \
    ((uint64_t *)(v))[0] = 0x6A09E667F3BCC908; \
    ((uint64_t *)(v))[1] = 0xBB67AE8584CAA73B; \
    ((uint64_t *)(v))[2] = 0x3C6EF372FE94F82B; \
    ((uint64_t *)(v))[3] = 0xA54FF53A5F1D36F1; \
    ((uint64_t *)(v))[4] = 0x510E527FADE682D1; \
    ((uint64_t *)(v))[5] = 0x9B05688C2B3E6C1F; \
    ((uint64_t *)(v))[6] = 0x1F83D9ABFB41BD6B; \
    ((uint64_t *)(v))[7] = 0x5BE0CD19137E2179; \
}
#endif

// cyclic right rotation
#ifndef ROTR64
#define ROTR64(x, y) (((x) >> (y)) ^ ((x) << (64 - (y))))
#endif

// G mixing function
#ifndef B2B_G
#define B2B_G(v, a, b, c, d, x, y)                                          \
{                                                                           \
    ((uint64_t *)(v))[a] += ((uint64_t *)(v))[b] + x;                       \
    ((uint64_t *)(v))[d]                                                    \
        = ROTR64(((uint64_t *)(v))[d] ^ ((uint64_t *)(v))[a], 32);          \
    ((uint64_t *)(v))[c] += ((uint64_t *)(v))[d];                           \
    ((uint64_t *)(v))[b]                                                    \
        = ROTR64(((uint64_t *)(v))[b] ^ ((uint64_t *)(v))[c], 24);          \
    ((uint64_t *)(v))[a] += ((uint64_t *)(v))[b] + y;                       \
    ((uint64_t *)(v))[d]                                                    \
        = ROTR64(((uint64_t *)(v))[d] ^ ((uint64_t *)(v))[a], 16);          \
    ((uint64_t *)(v))[c] += ((uint64_t *)(v))[d];                           \
    ((uint64_t *)(v))[b]                                                    \
        = ROTR64(((uint64_t *)(v))[b] ^ ((uint64_t *)(v))[c], 63);          \
}
#endif

// mixing rounds
#ifndef B2B_MIX
#define B2B_MIX(v, m)                                                     \
{                                                                         \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 1]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[ 3]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[ 5]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[ 7]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[ 9]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[10], ((uint64_t *)(m))[11]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[12], ((uint64_t *)(m))[13]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[14], ((uint64_t *)(m))[15]); \
                                                                          \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[14], ((uint64_t *)(m))[10]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[ 8]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[15]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[13], ((uint64_t *)(m))[ 6]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[12]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 2]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[11], ((uint64_t *)(m))[ 7]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[ 3]); \
                                                                          \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[11], ((uint64_t *)(m))[ 8]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[12], ((uint64_t *)(m))[ 0]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[ 2]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[15], ((uint64_t *)(m))[13]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[10], ((uint64_t *)(m))[14]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 3], ((uint64_t *)(m))[ 6]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 7], ((uint64_t *)(m))[ 1]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[ 4]); \
                                                                          \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 7], ((uint64_t *)(m))[ 9]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 3], ((uint64_t *)(m))[ 1]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[13], ((uint64_t *)(m))[12]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[11], ((uint64_t *)(m))[14]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[ 6]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[10]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[ 0]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[15], ((uint64_t *)(m))[ 8]); \
                                                                          \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[ 0]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[ 7]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[ 4]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[10], ((uint64_t *)(m))[15]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[14], ((uint64_t *)(m))[ 1]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[11], ((uint64_t *)(m))[12]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[ 8]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 3], ((uint64_t *)(m))[13]); \
                                                                          \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[12]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[10]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[11]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[ 3]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[13]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 7], ((uint64_t *)(m))[ 5]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[15], ((uint64_t *)(m))[14]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[ 9]); \
                                                                          \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[12], ((uint64_t *)(m))[ 5]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[15]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[14], ((uint64_t *)(m))[13]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[10]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 7]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[ 3]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[ 2]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[11]); \
                                                                          \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[13], ((uint64_t *)(m))[11]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 7], ((uint64_t *)(m))[14]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[12], ((uint64_t *)(m))[ 1]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 3], ((uint64_t *)(m))[ 9]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[ 0]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[15], ((uint64_t *)(m))[ 4]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[ 6]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[10]); \
                                                                          \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[15]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[14], ((uint64_t *)(m))[ 9]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[11], ((uint64_t *)(m))[ 3]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 8]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[12], ((uint64_t *)(m))[ 2]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[13], ((uint64_t *)(m))[ 7]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[ 4]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[10], ((uint64_t *)(m))[ 5]); \
                                                                          \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[10], ((uint64_t *)(m))[ 2]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[ 4]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 7], ((uint64_t *)(m))[ 6]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[ 5]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[15], ((uint64_t *)(m))[11]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[14]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 3], ((uint64_t *)(m))[12]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[13], ((uint64_t *)(m))[ 0]); \
                                                                          \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 1]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[ 3]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[ 5]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[ 7]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[ 9]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[10], ((uint64_t *)(m))[11]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[12], ((uint64_t *)(m))[13]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[14], ((uint64_t *)(m))[15]); \
                                                                          \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[14], ((uint64_t *)(m))[10]); \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[ 8]); \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[15]); \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[13], ((uint64_t *)(m))[ 6]); \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[12]); \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 2]); \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[11], ((uint64_t *)(m))[ 7]); \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[ 3]); \
}
#endif

// blake2b initialization
#ifndef B2B_INIT
#define B2B_INIT(ctx, aux)                                                  \
{                                                                           \
    ((blake2b_ctx *)(ctx))->t[0] += ((blake2b_ctx *)(ctx))->c;              \
    ((blake2b_ctx *)(ctx))->t[1]                                            \
        += 1 - !(((blake2b_ctx *)(ctx))->t[0] < ((blake2b_ctx *)(ctx))->c); \
                                                                            \
    ((uint64_t *)(aux))[0] = ((blake2b_ctx *)(ctx))->h[0];                  \
    ((uint64_t *)(aux))[1] = ((blake2b_ctx *)(ctx))->h[1];                  \
    ((uint64_t *)(aux))[2] = ((blake2b_ctx *)(ctx))->h[2];                  \
    ((uint64_t *)(aux))[3] = ((blake2b_ctx *)(ctx))->h[3];                  \
    ((uint64_t *)(aux))[4] = ((blake2b_ctx *)(ctx))->h[4];                  \
    ((uint64_t *)(aux))[5] = ((blake2b_ctx *)(ctx))->h[5];                  \
    ((uint64_t *)(aux))[6] = ((blake2b_ctx *)(ctx))->h[6];                  \
    ((uint64_t *)(aux))[7] = ((blake2b_ctx *)(ctx))->h[7];                  \
                                                                            \
    B2B_IV(aux + 8);                                                        \
}
#endif

// blake2b mixing 
#ifndef B2B_FINALIZE
#define B2B_FINALIZE(ctx, aux)                                               \
{                                                                            \
    ((uint64_t *)(aux))[16] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[ 0]; \
    ((uint64_t *)(aux))[17] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[ 1]; \
    ((uint64_t *)(aux))[18] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[ 2]; \
    ((uint64_t *)(aux))[19] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[ 3]; \
    ((uint64_t *)(aux))[20] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[ 4]; \
    ((uint64_t *)(aux))[21] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[ 5]; \
    ((uint64_t *)(aux))[22] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[ 6]; \
    ((uint64_t *)(aux))[23] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[ 7]; \
    ((uint64_t *)(aux))[24] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[ 8]; \
    ((uint64_t *)(aux))[25] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[ 9]; \
    ((uint64_t *)(aux))[26] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[10]; \
    ((uint64_t *)(aux))[27] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[11]; \
    ((uint64_t *)(aux))[28] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[12]; \
    ((uint64_t *)(aux))[29] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[13]; \
    ((uint64_t *)(aux))[30] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[14]; \
    ((uint64_t *)(aux))[31] = ((uint64_t *)(((blake2b_ctx *)(ctx))->b))[15]; \
                                                                             \
    B2B_MIX(aux, aux + 16);                                                  \
                                                                             \
    ((blake2b_ctx *)(ctx))->h[0]                                             \
        ^= ((uint64_t *)(aux))[0] ^ ((uint64_t *)(aux))[ 8];                 \
    ((blake2b_ctx *)(ctx))->h[1]                                             \
        ^= ((uint64_t *)(aux))[1] ^ ((uint64_t *)(aux))[ 9];                 \
    ((blake2b_ctx *)(ctx))->h[2]                                             \
        ^= ((uint64_t *)(aux))[2] ^ ((uint64_t *)(aux))[10];                 \
    ((blake2b_ctx *)(ctx))->h[3]                                             \
        ^= ((uint64_t *)(aux))[3] ^ ((uint64_t *)(aux))[11];                 \
    ((blake2b_ctx *)(ctx))->h[4]                                             \
        ^= ((uint64_t *)(aux))[4] ^ ((uint64_t *)(aux))[12];                 \
    ((blake2b_ctx *)(ctx))->h[5]                                             \
        ^= ((uint64_t *)(aux))[5] ^ ((uint64_t *)(aux))[13];                 \
    ((blake2b_ctx *)(ctx))->h[6]                                             \
        ^= ((uint64_t *)(aux))[6] ^ ((uint64_t *)(aux))[14];                 \
    ((blake2b_ctx *)(ctx))->h[7]                                             \
        ^= ((uint64_t *)(aux))[7] ^ ((uint64_t *)(aux))[15];                 \
}
#endif

// blake2b intermediate mixing procedure
#ifndef B2B_H
#define B2B_H(ctx, aux)                                      \
{                                                            \
    B2B_INIT(ctx, aux);                                      \
                                                             \
    ((uint64_t *)(aux))[12] ^= ((blake2b_ctx *)(ctx))->t[0]; \
    ((uint64_t *)(aux))[13] ^= ((blake2b_ctx *)(ctx))->t[1]; \
                                                             \
    B2B_FINALIZE(ctx, aux);                                  \
                                                             \
    ((blake2b_ctx *)(ctx))->c = 0;                           \
}
#endif

// blake2b last mixing procedure
#ifndef B2B_H_LAST
#define B2B_H_LAST(ctx, aux)                                 \
{                                                            \
    B2B_INIT(ctx, aux);                                      \
                                                             \
    ((uint64_t *)(aux))[12] ^= ((blake2b_ctx *)(ctx))->t[0]; \
    ((uint64_t *)(aux))[13] ^= ((blake2b_ctx *)(ctx))->t[1]; \
    ((uint64_t *)(aux))[14] = ~((uint64_t *)(aux))[14];      \
                                                             \
    B2B_FINALIZE(ctx, aux);                                  \
}
#endif

////////////////////////////////////////////////////////////////////////////////
#ifndef CUDA_CALL
#define CUDA_CALL(x)                                       \
    do {                                                   \
        if ((x) != cudaSuccess)                            \
        {                                                  \
            printf("ERROR at %s: %d\n",__FILE__,__LINE__); \
            return EXIT_FAILURE;                           \
        }                                                  \
    } while (0)
#endif

#ifndef CURAND_CALL
#define CURAND_CALL(x)                                 \
do {                                                   \
    if ((x) != CURAND_STATUS_SUCCESS)                  \
    {                                                  \
        printf("ERROR at %s: %d\n",__FILE__,__LINE__); \
        return EXIT_FAILURE;                           \
    }                                                  \
} while (0)
#endif

#endif // DEFINITIONS_H
