#include <stdio.h>
#include <inttypes.h>

#include "blake2b.h"

// Deterministic sequences (Fibonacci generator).
static void selftest_seq(uint8_t *out, size_t len, uint32_t seed)
{
    size_t i;
    uint32_t t, a , b;

    a = 0xDEAD4BAD * seed;              // prime
    b = 1;

    for (i = 0; i < len; i++) {         // fill the buf
        t = a + b;
        a = b;
        b = t;
        out[i] = (t >> 24) & 0xFF;
    }
}

// BLAKE2b self-test validation. Return 0 when OK.
int blake2b_selftest()
{
    // grand hash of hash results
    const uint8_t blake2b_res[32] = {
        0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD,
        0x10, 0xF5, 0x06, 0xC6, 0x1E, 0x29, 0xDA, 0x56,
        0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD, 0x2E, 0x73,
        0x7F, 0x5E, 0x76, 0x5A, 0x7B, 0xCC, 0xD4, 0x75
    };

    // parameter sets
    const size_t b2b_md_len[4] = { 20, 32, 48, 64 };
    const size_t b2b_in_len[6] = { 0, 3, 128, 129, 255, 1024 };

    size_t i, j, outlen, inlen;
    uint8_t in[1024], md[64], key[64];
    blake2b_ctx ctx;

    // 256-bit hash for testing
    if (blake2b_init(&ctx, 32, NULL, 0))
    {
        return -1;
    }

    for (i = 0; i < 4; i++)
    {
        outlen = b2b_md_len[i];

        for (j = 0; j < 6; j++)
        {
            inlen = b2b_in_len[j];

            selftest_seq(in, inlen, inlen);     // unkeyed hash
            blake2b(md, outlen, NULL, 0, in, inlen);
            blake2b_update(&ctx, md, outlen);   // hash the hash

            selftest_seq(key, outlen, outlen);  // keyed hash
            blake2b(md, outlen, key, outlen, in, inlen);
            blake2b_update(&ctx, md, outlen);   // hash the hash
        }
    }

    // compute and compare the hash of hashes
    blake2b_final(&ctx, md);

    for (i = 0; i < 32; i++)
    {
        if (md[i] != blake2b_res[i])
        {
            return -1;
        }
    }

    return 0;
}

// Test driver.
int main(int argc, char **argv)
{
    // for original hash
    // printf("blake2b_selftest() = %s\n", blake2b_selftest() ? "FAIL" : "OK");

///    /// uint8_t in[3] = { 0xFF, 0xFF, 0xFF };
///    uint8_t in[33] = {    0, 0xFF, 0xFF, 0xFF, 0xFF,
///                             0xFF, 0xFF, 0xFF, 0xFF,
///                             0xFF, 0xFF, 0xFF, 0xFF,
///                             0xFF, 0xFF, 0xFF, 0xFF, 
///                             0xFF, 0xFF, 0xFF, 0xFF,
///                             0xFF, 0xFF, 0xFF, 0xFF,
///                             0xFF, 0xFF, 0xFF, 0xFF,
///                             0xFF, 0xFF, 0xFF, 0xFF
///    };
    uint32_t out[8];
    uint32_t med[8];
///
///    int i;
///    //// for (i = 1; i <= 32; ++i)
///    //// {
///    ////     blake2b(med, 32, NULL, 0, in, i);
///    ////     ///blake2b(out, 32, NULL, 0, NULL, 0);
///
///    //// /// #define CONVERT(p)                            \
///    //// /// {                                             \
///    //// ///     *((uint32_t *)(p))                        \
///    //// ///     = (((uint32_t)((uint8_t *)(p))[0]) ^      \
///    //// ///     (((uint32_t)((uint8_t *)(p))[1]) << 8) ^  \
///    //// ///     (((uint32_t)((uint8_t *)(p))[2]) << 16) ^ \
///    //// ///     (((uint32_t)((uint8_t *)(p))[3]) << 24)); \
///    //// /// }
///
///    ////     // CONVERT(med);
///
///    ////     // blake2b(out, 32, NULL, 0, med, 32);
///
///    ////     printf(
///    ////         "blake2b-256 = 0x%016lX %016lX %016lX %016lX\n",
///    ////         ((uint64_t *)med)[0],
///    ////         ((uint64_t *)med)[1],
///    ////         ((uint64_t *)med)[2],
///    ////         ((uint64_t *)med)[3]
///    ////     );
///    //// }
///
///    uint8_t innew[32]= { 
///        0xa1, 0x12, 0xc9, 0x4a,
///        0x15, 0x22, 0x28, 0x82,
///        0xd4, 0x88, 0xae, 0xee,
///        0xaf, 0x35, 0x33, 0x60,
///        0x73, 0x28, 0xf6, 0xb3,
///        0xb7, 0xf6, 0xba, 0x6d,
///        0x88, 0xa0, 0xea, 0xb6,
///        0xdd, 0x54, 0x33, 0x96
///    };
///
///    uint8_t inold[2] = {0xaa, 0xFF};
///
///    blake2b(med, 32, NULL, 0, innew, 32);
///    /// printf(
///    ///     "blake2b-256 = 0x%016lX %016lX %016lX %016lX\n",
///    ///     ((uint64_t *)med)[0],
///    ///     ((uint64_t *)med)[1],
///    ///     ((uint64_t *)med)[2],
///    ///     ((uint64_t *)med)[3]
///    /// );
///    printf(
///        "blake2b-256 = 0x%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8" %"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8" %"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8" %"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"\n",
///        ((uint8_t *)med)[0],
///        ((uint8_t *)med)[1],
///        ((uint8_t *)med)[2],
///        ((uint8_t *)med)[3],
///        ((uint8_t *)med)[4],
///        ((uint8_t *)med)[5],
///        ((uint8_t *)med)[6],
///        ((uint8_t *)med)[7],
///        ((uint8_t *)med)[8],
///        ((uint8_t *)med)[9],
///        ((uint8_t *)med)[10],
///        ((uint8_t *)med)[11],
///        ((uint8_t *)med)[12],
///        ((uint8_t *)med)[13],
///        ((uint8_t *)med)[14],
///        ((uint8_t *)med)[15],
///        ((uint8_t *)med)[16],
///        ((uint8_t *)med)[17],
///        ((uint8_t *)med)[18],
///        ((uint8_t *)med)[19],
///        ((uint8_t *)med)[20],
///        ((uint8_t *)med)[21],
///        ((uint8_t *)med)[22],
///        ((uint8_t *)med)[23],
///        ((uint8_t *)med)[24],
///        ((uint8_t *)med)[25],
///        ((uint8_t *)med)[26],
///        ((uint8_t *)med)[27],
///        ((uint8_t *)med)[28],
///        ((uint8_t *)med)[29],
///        ((uint8_t *)med)[30],
///        ((uint8_t *)med)[31]
///    );
///    blake2b(med, 32, NULL, 0, inold, 2);

#define GET_REVERSE(p)                         \
    ((((uint64_t)((uint8_t *)(p))[0]) << 56) ^ \
    (((uint64_t)((uint8_t *)(p))[1]) << 48) ^  \
    (((uint64_t)((uint8_t *)(p))[2]) << 40) ^  \
    (((uint64_t)((uint8_t *)(p))[3]) << 32) ^  \
    (((uint64_t)((uint8_t *)(p))[4]) << 24) ^  \
    (((uint64_t)((uint8_t *)(p))[5]) << 16) ^  \
    (((uint64_t)((uint8_t *)(p))[6]) << 8) ^   \
    ((uint64_t)((uint8_t *)(p))[7]))

///    blake2b(out, 32, NULL, 0, med, 32);
///
///    printf(
///        "blake2b-256 = 0x%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8" %"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8" %"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8" %"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"\n",
///        ((uint8_t *)med)[0],
///        ((uint8_t *)med)[1],
///        ((uint8_t *)med)[2],
///        ((uint8_t *)med)[3],
///        ((uint8_t *)med)[4],
///        ((uint8_t *)med)[5],
///        ((uint8_t *)med)[6],
///        ((uint8_t *)med)[7],
///        ((uint8_t *)med)[8],
///        ((uint8_t *)med)[9],
///        ((uint8_t *)med)[10],
///        ((uint8_t *)med)[11],
///        ((uint8_t *)med)[12],
///        ((uint8_t *)med)[13],
///        ((uint8_t *)med)[14],
///        ((uint8_t *)med)[15],
///        ((uint8_t *)med)[16],
///        ((uint8_t *)med)[17],
///        ((uint8_t *)med)[18],
///        ((uint8_t *)med)[19],
///        ((uint8_t *)med)[20],
///        ((uint8_t *)med)[21],
///        ((uint8_t *)med)[22],
///        ((uint8_t *)med)[23],
///        ((uint8_t *)med)[24],
///        ((uint8_t *)med)[25],
///        ((uint8_t *)med)[26],
///        ((uint8_t *)med)[27],
///        ((uint8_t *)med)[28],
///        ((uint8_t *)med)[29],
///        ((uint8_t *)med)[30],
///        ((uint8_t *)med)[31]
///    );
///
///    printf(
///        "blake2b-256 = 0x%016lX %016lX %016lX %016lX\n",
///        GET_REVERSE(((uint64_t *)med)),
///        GET_REVERSE(((uint64_t *)med) + 1),
///        GET_REVERSE(((uint64_t *)med) + 2),
///        GET_REVERSE(((uint64_t *)med) + 3)
///    );
///
///    /// printf(
///    ///     "blake2b-256 = 0x%016lX %016lX %016lX %016lX\n",
///    ///     ((uint64_t *)out)[0],
///    ///     ((uint64_t *)out)[1],
///    ///     ((uint64_t *)out)[2],
///    ///     ((uint64_t *)out)[3]
///    /// );
///
///    printf(
///        "blake2b-256 = 0x%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8" %"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8" %"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8" %"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"%"PRIx8"\n",
///        ((uint8_t *)out)[0],
///        ((uint8_t *)out)[1],
///        ((uint8_t *)out)[2],
///        ((uint8_t *)out)[3],
///        ((uint8_t *)out)[4],
///        ((uint8_t *)out)[5],
///        ((uint8_t *)out)[6],
///        ((uint8_t *)out)[7],
///        ((uint8_t *)out)[8],
///        ((uint8_t *)out)[9],
///        ((uint8_t *)out)[10],
///        ((uint8_t *)out)[11],
///        ((uint8_t *)out)[12],
///        ((uint8_t *)out)[13],
///        ((uint8_t *)out)[14],
///        ((uint8_t *)out)[15],
///        ((uint8_t *)out)[16],
///        ((uint8_t *)out)[17],
///        ((uint8_t *)out)[18],
///        ((uint8_t *)out)[19],
///        ((uint8_t *)out)[20],
///        ((uint8_t *)out)[21],
///        ((uint8_t *)out)[22],
///        ((uint8_t *)out)[23],
///        ((uint8_t *)out)[24],
///        ((uint8_t *)out)[25],
///        ((uint8_t *)out)[26],
///        ((uint8_t *)out)[27],
///        ((uint8_t *)out)[28],
///        ((uint8_t *)out)[29],
///        ((uint8_t *)out)[30],
///        ((uint8_t *)out)[31]
///    );


    uint32_t bound_h[8];
    uint32_t mes_h[8];
    uint32_t sk_h[8];
    uint8_t pk_h[33];
    uint32_t x_h[8];
    uint8_t w_h[33];

    if (argc == 1)
    {
        printf("Please, specify the input filename\n");
        fflush(stdout);

        return -1;
    }

    readInput(argv[1], bound_h, mes_h, sk_h, pk_h, x_h, w_h);

    blake2b_ctx ctx;
    if (blake2b_init(&ctx, 32, NULL, 0))
    {
        return -1;
    }

    uint8_t a[4] = {0, 0, 0, 1};

    blake2b_update(&ctx, a, 4);

    uint32_t j;
    uint8_t next[0x2000];
    uint8_t next2[0x2000];

    int i;
    for (j = 0; j < 1024; ++j)
    {
        for (i = 0; i < 8; ++i)
        {
            next[j * 8 + i] = (i == 7)? (j & 0xFF): ((i == 6)? ((j >> 8) & 0xFF): 0);
            // printf("%d %d\n", next[j * 8 + i],
            //     (!((7 - (i)) >> 1) * (j >> (((~(i)) & 1) << 3))) & 0xFF);

            // blake2b_update(&ctx, next + j * 8 + i, 1);
        }
    }

    for (j = 0; j < 0x2000; ++j)
    {
        // printf("%d %d\n", next[j],
        //     (!((7 - (j & 7)) >> 1) * ((j >> 3) >> (((~(j & 7)) & 1) << 3))) & 0xFF);
        next[j] = (!((uint8_t)(7 - (j & 7)) >> 1) * ((j >> 3) >> (((~(j & 7)) & 1) << 3))) & 0xFF;

        // printf("%d %d\n", ctx.c, j);
            ///ctx.b[ctx.c++] = next[j];
            blake2b_update(&ctx, next + j, 1);
        // printf("%d %d\n", ctx->c, j);
        ///if (ctx.c == 128)
        ///    ctx.c = 0;
    }

    blake2b_update(&ctx, pk_h, 33);
    blake2b_update(&ctx, mes_h, 32);
    blake2b_update(&ctx, w_h, 33);

    blake2b_final(&ctx, out);
    
    printf(
        "blake2b-256 = 0x%016lX %016lX %016lX %016lX\n",
        GET_REVERSE(((uint64_t *)out) + 0),
        GET_REVERSE(((uint64_t *)out) + 1),
        GET_REVERSE(((uint64_t *)out) + 2),
        GET_REVERSE(((uint64_t *)out) + 3)
    );

    //// uint32_t a[1] = { 0x1 };
    //// printf("%"PRIx8"\n", ((uint8_t *)a)[0]);
    //// fflush(stdout);

    return 0;
}

int readInput(
    char * filename,
    void * bound,
    void * mes,
    void * sk,
    void * pk,
    void * x,
    void * w
) {
    FILE * in = fopen(filename, "r");

    int status;

    int i;

#define INPLACE_REVERSE_ENDIAN(p)                \
{                                                \
    *((uint64_t *)(p))                           \
    = ((((uint64_t)((uint8_t *)(p))[0]) << 56) ^ \
    (((uint64_t)((uint8_t *)(p))[1]) << 48) ^    \
    (((uint64_t)((uint8_t *)(p))[2]) << 40) ^    \
    (((uint64_t)((uint8_t *)(p))[3]) << 32) ^    \
    (((uint64_t)((uint8_t *)(p))[4]) << 24) ^    \
    (((uint64_t)((uint8_t *)(p))[5]) << 16) ^    \
    (((uint64_t)((uint8_t *)(p))[6]) << 8) ^     \
    ((uint64_t)((uint8_t *)(p))[7]));            \
}

#define SCAN(x)                                  \
for (i = 0; i < 8 >> 1; ++i)       \
{                                                \
    status = fscanf(                             \
        in, "%"SCNx64"\n", (uint64_t *)(x) + i   \
    );                                           \
                                                 \
    INPLACE_REVERSE_ENDIAN((uint64_t *)(x) + i); \
}

    SCAN(bound);
    SCAN(mes);
    SCAN(sk);

    status = fscanf(in, "%"SCNx8"\n", (uint8_t *)pk);
    SCAN((uint8_t *)pk + 1);

    SCAN(x);

    status = fscanf(in, "%"SCNx8"\n", (uint8_t *)w);
    SCAN((uint8_t *)w + 1);

    /// printf(
    ///     "blake2b-256 = 0x%016lX %016lX %016lX %016lX\n",
    ///     REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w + 1))),
    ///     REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w + 1)) + 1),
    ///     REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w + 1)) + 2),
    ///     REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w + 1)) + 3)
    /// );

#undef SCAN
#undef INPLACE_REVERSE_ENDIAN

    fclose(in);

    return status;
}
