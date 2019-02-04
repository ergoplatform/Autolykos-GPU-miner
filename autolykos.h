#ifndef AUTOLYKOS_H
#define AUTOLYKOS_H

#include <stdint.h>
#include <stddef.h>

// keys, hashes and nonces size in bytes
#define NUM_BYTE_SIZE 32

// number of indices
#define K_LEN         32
// boundary for puzzle
#define B_LEN         10
// load of hashes per thread
#define H_LEN         4                  
// total load of hashes per round
#define L_LEN         0x3D090        // H_LEN * 10^6

// mod 2^26 mask
#define N_MASK        0x01FFFFFF

// block mining kernel grid & block sizes 
#define G_DIM         15625
#define B_DIM         64             // G_DIM * B_DIM = 10^6

// 64 bits
#define Q1            0x14DEF9DEA2F79CD6
#define Q0            0x5812631A5CF5D3ED

// 0xF * Q -- maximal multiplier of Q < 2^256
#define FQ3           0xF000000000000000
#define FQ2           1
#define FQ1           0x3910A40B8C82308F
#define FQ0           0x2913CE8B72676AE3

// 32 bits
#define q3_s          "0x14DEF9DE"
#define q2_s          "0xA2F79CD6"
#define q1_s          "0x5812631A"
#define q0_s          "0x5CF5D3ED"

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

// First iteration of hashes precalculation
__global__ void initPrehash(
    const void * data,
    // hashes
    void * res
);

__global__ void finalizePrehash(
    const void * data,
    // hashes
    void * res
);

// unfinalized hash of message
void initHash(
    // context
    blake2b_ctx * ctx,
    // optional secret key
    const void * key,
    // message
    const void * mes,
    uint32_t meslen
);

// block mining iteration
__global__ void blockMining(
    const void * data,
    // precalculated hashes
    const void * hash,
    // pregenerated nonces
    const void * non,
    // results
    uint32_t * res
);

#endif // AUTOLYKOS_H
