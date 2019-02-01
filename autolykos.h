#ifndef AUTOLYKOS_H
#define AUTOLYKOS_H

#include <stdint.h>
#include <stddef.h>

// Parameters
#define k 32
#define N 0x4000000 // 2^26
#define L 0xF4240   // 1000000

// 64 bits
#define Q1 0x14DEF9DEA2F79CD6
#define Q0 0x5812631A5CF5D3ED

// state context
typedef struct {
    // input buffer
    uint8_t b[128];
    // chained state
    uint64_t h[8];
    // total number of bytes
    uint64_t t[2];
    // counter for b
    uint32_t c;
    // digest size
    uint32_t outlen;
} blake2b_ctx;

__global__ void blockMining(
    // context
    blake2b_ctx * ctx,
    // optional secret key
    const void * key,
    uint32_t keylen,
    // message
    const void * in,
    uint32_t inlen,
    // pregenerated nonces
    const void * non,
    // hashes
    void * out,
    uint32_t outlen
);

#endif // AUTOLYKOS_H
