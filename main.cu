// test_main.cu
// Self test Modules for BLAKE2b and BLAKE2s -- and a stub main().

#include <stdio.h>

#include "blake2b.h"

// Deterministic sequences (Fibonacci generator).
static void selftest_seq(uint8_t *out, size_t len, uint32_t seed)
{
    size_t i;
    uint32_t t, a, b;

    a = 0xDEAD4BAD * seed;              // prime
    b = 1;

    for (i = 0; i < len; ++i)         // fill the buf
    {
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
    const size_t b2b_md_len[4] = {20, 32, 48, 64};
    const size_t b2b_in_len[6] = {0, 3, 128, 129, 255, 1024};

    size_t i, j, outlen, inlen;
    uint8_t in[1024], md[64], key[64];
    blake2b_ctx ctx;

    // 256-bit hash for testing
    if (blake2b_init(&ctx, 32, NULL, 0))
    {
        return -1;
    }

    blake2b_ctx * ctxptr;
    cudaMalloc(&ctxptr, sizeof(blake2b_ctx));

    void * d_out;
    void * d_key;
    void * d_in;

    cudaMalloc(&d_out, 64 * sizeof(uint8_t));
    cudaMalloc(&d_key, 64 * sizeof(uint8_t));
    cudaMalloc(&d_in, 1024 * sizeof(uint8_t));

    for (i = 0; i < 4; ++i)
    {
        outlen = b2b_md_len[i];

        for (j = 0; j < 6; ++j)
        {
            inlen = b2b_in_len[j];

            selftest_seq(in, inlen, inlen);     // unkeyed hash

            cudaMemcpy(d_in, in, 1024 * sizeof(uint8_t), cudaMemcpyHostToDevice);
            blake2b<<<1, 1>>>(ctxptr, d_out, outlen, NULL, 0, d_in, inlen);
            cudaMemcpy(md, d_out, 64 * sizeof(uint8_t), cudaMemcpyDeviceToHost);
            //blake2b<<<1, 1>>>(ctxptr, md, outlen, NULL, 0, in, inlen);

            blake2b_update(&ctx, md, outlen);   // hash the hash

            selftest_seq(key, outlen, outlen);  // keyed hash

            cudaMemcpy(d_key, key, 64 * sizeof(uint8_t), cudaMemcpyHostToDevice);
            cudaMemcpy(d_in, in, 1024 * sizeof(uint8_t), cudaMemcpyHostToDevice);
            blake2b<<<1, 1>>>(ctxptr, d_out, outlen, d_key, outlen, d_in, inlen);
            cudaMemcpy(md, d_out, 64 * sizeof(uint8_t), cudaMemcpyDeviceToHost);
            //blake2b<<<1, 1>>>(ctxptr, md, outlen, key, outlen, in, inlen);

            blake2b_update(&ctx, md, outlen);   // hash the hash
        }
    }

    cudaFree(d_out);
    cudaFree(d_key);
    cudaFree(d_in);

    // compute and compare the hash of hashes
    blake2b_final(&ctx, md);

    for (i = 0; i < 32; ++i)
    {
        if (md[i] != blake2b_res[i])
        {
            return -1;
        }
    }

    return 0;
}

int parallelBlockMining(
)
{
    curandState * d_state;
    cudaMalloc(&d_state, nThreads * nBlocks);

    blockMining<<<nBlocks, nThreads>>>(
        d_state
    );

    cudaFree(d_state);

    return 0;
}

int main(int argc, char ** argv)
{
   printf("blake2b_selftest() = %s\n", blake2b_selftest()? "FAIL": "OK");

   return 0;
}

