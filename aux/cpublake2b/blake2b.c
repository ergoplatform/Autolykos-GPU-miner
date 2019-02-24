#include "blake2b.h"

// Initialization Vector.
static const uint64_t blake2b_iv[8] = {
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

static const uint8_t sigma[12][16] = {
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

// Compression function. "last" flag indicates last block.
static void blake2b_compress(
    blake2b_ctx * ctx,
    int last
) {
    int i;
    uint64_t v[16];
    uint64_t m[16];

    // Initialization Vector.
    static const uint64_t blake2b_iv[8] = {
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
    };

    static const uint8_t sigma[12][16] = {
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

    // init work variables
    for (i = 0; i < 8; ++i)
    {
        v[i] = ctx->h[i];
        v[i + 8] = blake2b_iv[i];
    }

    // low 64 bits of offset             
    v[12] ^= ctx->t[0];
    // high 64 bits
    v[13] ^= ctx->t[1];
    // last block flag set ?
    if (last)
    {
        v[14] = ~v[14];
    }

    // get little-endian words
    for (i = 0; i < 16; i++)
    {
        m[i] = B2B_GET64(&ctx->b[8 * i]);
    }

    // twelve rounds
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
}

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 64 gives the digest size in bytes.
//      Secret key (also <= 64 bytes) is optional (keylen = 0).
int blake2b_init(
    blake2b_ctx * ctx,
    size_t outlen,
    const void * key,
    // (keylen=0: no key)
    size_t keylen
) {
    size_t k;

    if (outlen == 0 || outlen > 64 || keylen > 64)
    {
        // illegal parameters
        return -1;
    }

    // state, "param block"
    for (k = 0; k < 8; ++k)
    {
        ctx->h[k] = blake2b_iv[k];
    }

    ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

    // input count low word
    ctx->t[0] = 0;
    // input count high word
    ctx->t[1] = 0;
    // pointer within buffer
    ctx->c = 0;
    ctx->outlen = outlen;

    // zero input block
    for (k = keylen; k < 128; ++k)
    {
        ctx->b[k] = 0;
    }

    if (keylen > 0)
    {
        blake2b_update(ctx, key, keylen);
        // at the end
        ctx->c = 128;
    }

    return 0;
}

// Add "inlen" bytes from "in" into the hash.
void blake2b_update(
    blake2b_ctx * ctx,
    // data
    const void * in,
    // data byte size
    size_t inlen
) {
    size_t k;

    for (k = 0; k < inlen; ++k)
    {
        // buffer full ?
        if (ctx->c == 128)
        {
            // add counters
            ctx->t[0] += ctx->c;

            // carry overflow ?
            if (ctx->t[0] < ctx->c)
            {
                // high word
                ctx->t[1]++;
            }

            // compress (not last)
            blake2b_compress(ctx, 0);
            // counter to zero
            ctx->c = 0;
        }

        ctx->b[ctx->c++] = ((const uint8_t *) in)[k];
    }
}

// Generate the message digest (size given in init).
//      Result placed in "out".
void blake2b_final(
    blake2b_ctx * ctx,
    void * out
) {
    size_t k;

    // mark last block offset
    ctx->t[0] += ctx->c;

    // carry overflow
    if (ctx->t[0] < ctx->c)
    {
        // high word
        ctx->t[1]++;
    }

    // fill up with zeros
    while (ctx->c < 128)
    {
        ctx->b[ctx->c++] = 0;
    }

    // final block flag = 1
    blake2b_compress(ctx, 1);

    // little endian convert and store
    for (k = 0; k < ctx->outlen; ++k)
    {
        ((uint8_t *) out)[k] = (ctx->h[k >> 3] >> (8 * (k & 7))) & 0xFF;
    }

    for (k = 0; k < ctx->outlen; ++k)
    {
        /// ((uint8_t *)out)[k] = (ctx->h[3 - (k >> 3)] >> (8 * ((127 - k) & 7))) & 0xFF;
        ((uint8_t *)out)[k] = (ctx->h[3 - (k >> 3)] >> (((127 - k) & 7) << 3)) & 0xFF;
    }
}

// Convenience function for all-in-one computation.
void blake2b(
    void * out,
    size_t outlen,
    const void * key,
    size_t keylen,
    const void * in,
    size_t inlen
) {
    blake2b_ctx ctx;

    if (blake2b_init(&ctx, outlen, key, keylen))
    {
        return;
    }

    blake2b_update(&ctx, in, inlen);
    blake2b_final(&ctx, out);

    return;
}
