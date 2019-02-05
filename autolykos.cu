#include "autolykos.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cuda.h>
#include <curand.h>

#define CUDA_CALL(x) do { if((x) != cudaSuccess) { \
printf("Error at %s:%d\n",__FILE__,__LINE__);      \
return EXIT_FAILURE;}} while (0)

#define CURAND_CALL(x) do { if((x) != CURAND_STATUS_SUCCESS) { \
printf("Error at %s:%d\n",__FILE__,__LINE__);                  \
return EXIT_FAILURE;}} while (0)

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
// template <unsigned int blockSize, bool nIsPow2>
// __global__ void
// reduce6(uint32_t *g_idata, uint32_t *g_odata, uint32_t n)
// {
//     // Handle to thread block group
//     cg::thread_block cta = cg::this_thread_block();
//     uint32_t * sdata = SharedMemory<uint32_t>();
// 
//     // perform first level of reduction,
//     // reading from global memory, writing to shared memory
//     unsigned int tid = threadIdx.x;
//     unsigned int i = blockIdx.x * blockSize * 2 + threadIdx.x;
//     unsigned int gridSize = blockSize * 2 * gridDim.x;
// 
//     uint32_t mySum = 0;
// 
//     // we reduce multiple elements per thread.  The number is determined by the
//     // number of active thread blocks (via gridDim).  More blocks will result
//     // in a larger gridSize and therefore fewer elements per thread
//     while (i < n)
//     {
//         mySum += g_idata[i];
// 
//         // ensure we don't read out of bounds -- this is optimized away for powerOf2 sized arrays
//         if (nIsPow2 || i + blockSize < n)
//             mySum += g_idata[i+blockSize];
// 
//         i += gridSize;
//     }
// 
//     // each thread puts its local sum into shared memory
//     sdata[tid] = mySum;
//     cg::sync(cta);
// 
// 
//     // do reduction in shared mem
//     if ((blockSize >= 512) && (tid < 256))
//     {
//         sdata[tid] = mySum = mySum + sdata[tid + 256];
//     }
// 
//     cg::sync(cta);
// 
//     if ((blockSize >= 256) &&(tid < 128))
//     {
//         sdata[tid] = mySum = mySum + sdata[tid + 128];
//     }
// 
//     cg::sync(cta);
// 
//     if ((blockSize >= 128) && (tid <  64))
//     {
//        sdata[tid] = mySum = mySum + sdata[tid +  64];
//     }
// 
//     cg::sync(cta);
// 
// #if (__CUDA_ARCH__ >= 300 )
//     if (tid < 32)
//     {
//         cg::coalesced_group active = cg::coalesced_threads();
// 
//         // Fetch final intermediate sum from 2nd warp
//         if (blockSize >=  64) mySum += sdata[tid + 32];
//         // Reduce final warp using shuffle
//         for (int offset = warpSize / 2; offset > 0; offset /= 2) 
//         {
//              mySum += active.shfl_down(mySum, offset);
//         }
//     }
// #else
//     // fully unroll reduction within a single warp
//     if ((blockSize >=  64) && (tid < 32))
//     {
//         sdata[tid] = mySum = mySum + sdata[tid + 32];
//     }
// 
//     cg::sync(cta);
// 
//     if ((blockSize >=  32) && (tid < 16))
//     {
//         sdata[tid] = mySum = mySum + sdata[tid + 16];
//     }
// 
//     cg::sync(cta);
// 
//     if ((blockSize >=  16) && (tid <  8))
//     {
//         sdata[tid] = mySum = mySum + sdata[tid +  8];
//     }
// 
//     cg::sync(cta);
// 
//     if ((blockSize >=   8) && (tid <  4))
//     {
//         sdata[tid] = mySum = mySum + sdata[tid +  4];
//     }
// 
//     cg::sync(cta);
// 
//     if ((blockSize >=   4) && (tid <  2))
//     {
//         sdata[tid] = mySum = mySum + sdata[tid +  2];
//     }
// 
//     cg::sync(cta);
// 
//     if ((blockSize >=   2) && ( tid <  1))
//     {
//         sdata[tid] = mySum = mySum + sdata[tid +  1];
//     }
// 
//     cg::sync(cta);
// #endif
// 
//     // write result for this block to global mem
//     if (tid == 0) g_odata[blockIdx.x] = mySum;
// }
////////////////////////////////////////////////////////////////////////////////

template <uint32_t blockSize>
__device__ void warpReduce(volatile uint32_t * sdata, uint32_t tid)
{
    if (blockSize >= 64) { sdata[tid] += sdata[tid + 32]; }
    if (blockSize >= 32) { sdata[tid] += sdata[tid + 16]; }
    if (blockSize >= 16) { sdata[tid] += sdata[tid +  8]; }
    if (blockSize >=  8) { sdata[tid] += sdata[tid +  4]; }
    if (blockSize >=  4) { sdata[tid] += sdata[tid +  2]; }
    if (blockSize >=  2) { sdata[tid] += sdata[tid +  1]; }
}

template <uint32_t blockSize>
__global__ void reduce(
    uint32_t * g_idata,
    uint32_t * g_odata,
    uint32_t len
) {
    __shared__ uint32_t sdata[len];

    uint32_t tid = threadIdx.x;
    uint32_t i = blockIdx.x * blockSize * 2 + tid;
    uint32_t gridSize = blockSize * 2 * gridDim.x;

    sdata[tid] = 0;

    for ( ; i < len; i += gridSize)
    {
        sdata[tid] += g_idata[i] + g_idata[i + blockSize];
    }

    __syncthreads();

    //if (blockSize >= 512)
    //{
    //    if (tid < 256) { sdata[tid] += sdata[tid + 256]; }
    //    __syncthreads();
    //}

    //if (blockSize >= 256)
    //{
    //    if (tid < 128) { sdata[tid] += sdata[tid + 128]; }
    //    __syncthreads();
    //}

    //if (blockSize >= 128)
    //{
    //    if (tid < 64) { sdata[tid] += sdata[tid + 64]; }
    //    __syncthreads();
    //}

    if (tid < 32)
    {
        warpReduce(sdata, tid);
    }

    if (tid == 0)
    {
        g_odata[blockIdx.x] = sdata[0];
    }
}

////////////////////////////////////////////////////////////////////////////////
//  Initialize random generator
////////////////////////////////////////////////////////////////////////////////
void initRand(
    curandGenerator_t * gen,
    uint32_t ** non
) {
    CURAND_CALL(curandCreateGenerator(gen, CURAND_RNG_PSEUDO_MTGP32));
    CUDA_CALL(cudaMalloc((void **)non, L_SIZE * 4 * sizeof(uint32_t)));

    time_t rawtime;
    time(&rawtime);
    CURAND_CALL(curandSetPseudoRandomGeneratorSeed(gen, (uint64_t)rawtime));

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Main cycle
////////////////////////////////////////////////////////////////////////////////
int main(int argc, char ** argv)
{
    const uint64_t blake2b_iv[8] = {
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
    };

    const uint8_t sigma[12 * 16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
    };

    // host allocation
    blake2b_ctx * ctx_h = (blake2b_ctx *)malloc(sizeof(blake2b_ctx));
    // 256 bits
    uint32_t mes_h[8] = {
        0, 0, 0, 0, 0, 0, 0, 0
    }; 

    // L_SIZE * 256 bits
    //uint32_t * res_h = (uint32_t *)malloc(L_SIZE * 8 * sizeof(uint32_t)); 

    // device allocation
    void * data_d;
    CUDA_CALL(cudaMalloc((void **)&data_d, 2 * BDIM * sizeof(uint32_t)));
    CUDA_CALL(cudaMemcpy(
        data_d, (void *)blake2b_iv, 8 * sizeof(uint64_t), cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemcpy(
        (void *)((uint32_t *)data_d + 16), (void *)sigma, 192,
        cudaMemcpyHostToDevice
    ));

    // L_SIZE * 256 bits
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc((void **)&res_d, L_SIZE * 8 * sizeof(uint32_t)));

    int ind = -1;

    // intialize random generator
    curandGenerator_t gen;
    // L_SIZE * 256 bits
    uint32_t * non_d;
    initRand(&gen, &non_d);

    // secret key
    //>>>genKey();
    CUDA_CALL(cudaMemcpy(
        (void *)((uint32_t *)data_d + 64), sk_h, KEY_LEN * sizeof(uint8_t),
        cudaMemcpyHostToDevice
    ));

    while (1)
    {
        if (ind >= 0)
        {
            // one time secret key
            //>>>genKey();

            //>>>hash();
        }

        // generate nonces
        CURAND_CALL(curandGenerate(gen, non_d, L_SIZE * 8));

        // calculate unfinalized hash of message
        partialHash(ctx_h, sk_h, mes_h, 32);

        CUDA_CALL(cudaMemcpy(
            (void *)((uint32_t *)data_d + 64 + KEY_LEN / sizeof(uint32_t)),
            (void *)ctx_h, sizeof(blake2b_ctx), cudaMemcpyHostToDevice
        ));

        // calculate hashes
        blockMining<<<GDIM, BDIM>>>(ctx_d, hash_d, non_d, res_d);

        //>>>ind = findSolution(res);
    }

    CURAND_CALL(curandDestroyGenerator(gen));
    CUDA_CALL(cudaFree(non));
    CUDA_CALL(cudaFree(data_d));
    free(ctx_h);

    return 0;
}

