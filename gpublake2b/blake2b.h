// blake2b.h
// BLAKE2b Hashing Context and API Prototypes

#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <stdint.h>
#include <stddef.h>

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

// Mixing function
// All-in-one convenience function.
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
