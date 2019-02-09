#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <stdint.h>
#include <stddef.h>

// initialization vector
#ifndef B2B_IV
#define B2B_IV(v)              \
{                              \
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

// little-endian byte access
#ifndef B2B_GET64
#define B2B_GET64(p)                           \
    (((uint64_t) ((uint8_t *)(p))[0]) ^        \
    (((uint64_t) ((uint8_t *)(p))[1]) << 8) ^  \
    (((uint64_t) ((uint8_t *)(p))[2]) << 16) ^ \
    (((uint64_t) ((uint8_t *)(p))[3]) << 24) ^ \
    (((uint64_t) ((uint8_t *)(p))[4]) << 32) ^ \
    (((uint64_t) ((uint8_t *)(p))[5]) << 40) ^ \
    (((uint64_t) ((uint8_t *)(p))[6]) << 48) ^ \
    (((uint64_t) ((uint8_t *)(p))[7]) << 56))  
#endif

// cyclic right rotation
#ifndef ROTR64
#define ROTR64(x, y) (((x) >> (y)) ^ ((x) << (64 - (y))))
#endif

// G mixing function
#ifndef B2B_G
#define B2B_G(v, a, b, c, d, x, y)                                          \
{                                                                           \
    ((uint64_t *)(v))[a] = ((uint64_t *)(v))[a] + ((uint64_t *)(v))[b] + x; \
    ((uint64_t *)(v))[d]                                                    \
        = ROTR64(((uint64_t *)(v))[d] ^ ((uint64_t *)(v))[a], 32);          \
    ((uint64_t *)(v))[c] = ((uint64_t *)(v))[c] + ((uint64_t *)(v))[d];     \
    ((uint64_t *)(v))[b]                                                    \
        = ROTR64(((uint64_t *)(v))[b] ^ ((uint64_t *)(v))[c], 24);          \
    ((uint64_t *)(v))[a] = ((uint64_t *)(v))[a] + ((uint64_t *)(v))[b] + y; \
    ((uint64_t *)(v))[d]                                                    \
        = ROTR64(((uint64_t *)(v))[d] ^ ((uint64_t *)(v))[a], 16);          \
    ((uint64_t *)(v))[c] = ((uint64_t *)(v))[c] + ((uint64_t *)(v))[d];     \
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
#define B2B_FINALIZE(ctx, aux)                                            \
{                                                                         \
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
    B2B_MIX(aux, aux + 16);                                               \
                                                                          \
    ((blake2b_ctx *)(ctx))->h[0]                                          \
        ^= ((uint64_t *)(aux))[0] ^ ((uint64_t *)(aux))[ 8];              \
    ((blake2b_ctx *)(ctx))->h[1]                                          \
        ^= ((uint64_t *)(aux))[1] ^ ((uint64_t *)(aux))[ 9];              \
    ((blake2b_ctx *)(ctx))->h[2]                                          \
        ^= ((uint64_t *)(aux))[2] ^ ((uint64_t *)(aux))[10];              \
    ((blake2b_ctx *)(ctx))->h[3]                                          \
        ^= ((uint64_t *)(aux))[3] ^ ((uint64_t *)(aux))[11];              \
    ((blake2b_ctx *)(ctx))->h[4]                                          \
        ^= ((uint64_t *)(aux))[4] ^ ((uint64_t *)(aux))[12];              \
    ((blake2b_ctx *)(ctx))->h[5]                                          \
        ^= ((uint64_t *)(aux))[5] ^ ((uint64_t *)(aux))[13];              \
    ((blake2b_ctx *)(ctx))->h[6]                                          \
        ^= ((uint64_t *)(aux))[6] ^ ((uint64_t *)(aux))[14];              \
    ((blake2b_ctx *)(ctx))->h[7]                                          \
        ^= ((uint64_t *)(aux))[7] ^ ((uint64_t *)(aux))[15];              \
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
// state context
typedef struct {
    // input buffer
    uint8_t b[128];
    // chained state
    uint64_t h[8];
    // total number of bytes
    uint64_t t[2];
    // pointer for b[]
    uint32_t c;
    // digest size
    size_t outlen;
} blake2b_ctx;

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 64 gives the digest size in bytes.
//      Secret key (also <= 64 bytes) is optional (keylen = 0).
int blake2b_init(
    blake2b_ctx * ctx,
    uint32_t outlen,
    // secret key
    const void * key,
    uint32_t keylen
);

// Add "inlen" bytes from "in" into the hash.
void blake2b_update(
    // context
    blake2b_ctx * ctx,
    // data to be hashed
    const void * in,
    uint32_t inlen
);

// Generate the message digest (size given in init).
//      Result placed in "out".
void blake2b_final(
    blake2b_ctx * ctx,
    void * out
);

// Hash-function
__global__ void blake2b(
    blake2b_ctx * ctx, 
    // return buffer for digest
    void * out,
    uint32_t outlen,
    // optional secret key
    const void * key,
    uint32_t keylen,
    // data to be hashed
    const void * in,
    uint32_t inlen
);

#endif 
