#ifndef AUTOLYKOS_H
#define AUTOLYKOS_H

#include <stdint.h>
#include <stddef.h>

////////////////////////////////////////////////////////////////////////////////
//  Constants
////////////////////////////////////////////////////////////////////////////////
// keys, hashes and nonces size in bytes
#define NUM_BYTE_SIZE 32
// number of indices
#define K_LEN         32
// boundary for puzzle
#define B_LEN         10
// number of precalculated hashes
#define N_LEN         0x4000000          // 2^26
// mod 2^26 mask
#define N_MASK        0x01FFFFFF

////////////////////////////////////////////////////////////////////////////////
// total number of hash loads (threads) per round
#define L_LEN         0x100000           // 2^20
// number of hashes per thread
#define H_LEN         4                  

////////////////////////////////////////////////////////////////////////////////
// block mining kernel grid & block sizes 
#define G_DIM         0x4000
#define B_DIM         64                 // G_DIM * B_DIM = L_LEN

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
// 0xF * Q -- maximal multiplier of Q < 2^256
#define FQ3           0xF000000000000000
#define FQ2           1
#define FQ1           0x3910A40B8C82308F
#define FQ0           0x2913CE8B72676AE3

////////////////////////////////////////////////////////////////////////////////
// little-endian byte access
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

// cyclic right rotation
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
#define CUDA_CALL(x) do { if((x) != cudaSuccess) { \
printf("Error at %s:%d\n",__FILE__,__LINE__);      \
return EXIT_FAILURE;}} while (0)

#define CURAND_CALL(x) do { if((x) != CURAND_STATUS_SUCCESS) { \
printf("Error at %s:%d\n",__FILE__,__LINE__);                  \
return EXIT_FAILURE;}} while (0)

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
//  Prehash calculation
////////////////////////////////////////////////////////////////////////////////
// first iteration of hashes precalculation
__global__ void initPrehash(
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    uint32_t * unfinalized
);

// unfinalized hashes update
__global__ void updatePrehash(
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    uint32_t * unfinalized
);

// hashes by secret key multiplication mod q 
__global__ void finalizePrehash(
    const uint32_t * data,
    // hashes
    uint32_t * hash
);

////////////////////////////////////////////////////////////////////////////////
//  Validation
////////////////////////////////////////////////////////////////////////////////
// unfinalized hash of message
void initMining(
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
    // hash constants & secret key
    const uint32_t * data,
    // pregenerated nonces
    const uint32_t * non,
    // precalculated hashes
    const uint32_t * hash,
    // results
    uint32_t * res,
    uint32_t * unfinalized
);

////////////////////////////////////////////////////////////////////////////////
//  Reduction
////////////////////////////////////////////////////////////////////////////////
uint32_t ceilToPower(
    uint32_t x
);

template <uint32_t blockSize>
__device__ void warpNonZero(
    volatile uint32_t * sdata,
    uint32_t tid
);

template <uint32_t blockSize>
__global__ void blockNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out
);

void reduceNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out,
    uint32_t gridSize,
    uint32_t blockSize
);

uint32_t findNonZero(
    uint32_t * in,
    uint32_t * aux
);

#endif // AUTOLYKOS_H
