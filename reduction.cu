// reduction.cu

#include "autolykos.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cuda.h>

uint32_t ceilToPower(uint32_t x)
{
    --x;

    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;

    return ++x;
}

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

//template <uint32_t blockSize>
//__device__ void warpReduce(volatile uint32_t * sdata, uint32_t tid)
//{
//    if (blockSize >= 64) { sdata[tid] += sdata[tid + 32]; }
//    if (blockSize >= 32) { sdata[tid] += sdata[tid + 16]; }
//    if (blockSize >= 16) { sdata[tid] += sdata[tid +  8]; }
//    if (blockSize >=  8) { sdata[tid] += sdata[tid +  4]; }
//    if (blockSize >=  4) { sdata[tid] += sdata[tid +  2]; }
//    if (blockSize >=  2) { sdata[tid] += sdata[tid +  1]; }
//}
//
//template <uint32_t blockSize>
//__global__ void reduce(
//    uint32_t * g_idata,
//    uint32_t * g_odata,
//    uint32_t len
//) {
//    extern __shared__ uint32_t sdata[];
//
//    uint32_t tid = threadIdx.x;
//    uint32_t i = blockIdx.x * blockSize * 2 + tid;
//    uint32_t gridSize = blockSize * 2 * gridDim.x;
//
//    sdata[tid] = 0;
//
//    for ( ; i < len; i += gridSize)
//    {
//        sdata[tid] += g_idata[i] + g_idata[i + blockSize];
//    }
//
//    __syncthreads();
//
//    //if (blockSize >= 512)
//    //{
//    //    if (tid < 256) { sdata[tid] += sdata[tid + 256]; }
//    //    __syncthreads();
//    //}
//
//    //if (blockSize >= 256)
//    //{
//    //    if (tid < 128) { sdata[tid] += sdata[tid + 128]; }
//    //    __syncthreads();
//    //}
//
//    //if (blockSize >= 128)
//    //{
//    //    if (tid < 64) { sdata[tid] += sdata[tid + 64]; }
//    //    __syncthreads();
//    //}
//
//    if (tid < 32)
//    {
//        warpReduce(sdata, tid);
//    }
//
//    if (tid == 0)
//    {
//        g_odata[blockIdx.x] = sdata[0];
//    }
//}

////////////////////////////////////////////////////////////////////////////////
//  Find non zero item in warp
////////////////////////////////////////////////////////////////////////////////
template <uint32_t blockSize>
__device__ void warpNonZero(
    volatile uint32_t * sdata,
    uint32_t tid
) {
    if (blockSize >= 64) { sdata[tid] += !sdata[tid] * sdata[tid + 32]; }
    if (blockSize >= 32) { sdata[tid] += !sdata[tid] * sdata[tid + 16]; }
    if (blockSize >= 16) { sdata[tid] += !sdata[tid] * sdata[tid +  8]; }
    if (blockSize >=  8) { sdata[tid] += !sdata[tid] * sdata[tid +  4]; }
    if (blockSize >=  4) { sdata[tid] += !sdata[tid] * sdata[tid +  2]; }
    if (blockSize >=  2) { sdata[tid] += !sdata[tid] * sdata[tid +  1]; }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Find non zero item in block
////////////////////////////////////////////////////////////////////////////////
template <uint32_t blockSize>
__global__ void blockNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out
) {
    uint32_t tid = threadIdx.x;

    __shared__ uint32_t sdata[B_DIM];
    sdata[tid] = 0;

    for (
        uint32_t i = 2 * blockIdx.x * blockSize + tid;
        i < inlen;
        i += 2 * blockSize * gridDim.x
    ) {
        sdata[tid] += !sdata[tid]
            * (in[i] + !(i + blockSize >= inlen) * !in[i] * in[i + blockSize]);
    }

    __syncthreads();

    if (tid < 32)
    {
        warpNonZero<blockSize>(sdata, tid);
    }

    if (tid == 0)
    {
        out[blockIdx.x] = sdata[0];
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Find non zero item in each block of array
////////////////////////////////////////////////////////////////////////////////
void reduceNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out,
    uint32_t gridSize,
    uint32_t blockSize
) {
    //printf("AAAA\n");
    //fflush(stdout);
    switch (blockSize)
    {
        case 64:
            blockNonZero<64><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 32:
            blockNonZero<32><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 16:
            blockNonZero<16><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 8:
            blockNonZero< 8><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 4:
            blockNonZero< 4><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 2:
            blockNonZero< 2><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 1:
            blockNonZero< 1><<<gridSize, blockSize>>>(in, inlen, out);
            break;
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Find non zero item in array
////////////////////////////////////////////////////////////////////////////////
uint32_t findNonZero(
    uint32_t * data,
    uint32_t * aux
) {
    uint32_t res;
    uint32_t inlen = 0x4000000; // 1 << 26;
    uint32_t gridSize = 1 + (inlen - 1) / (2 * B_DIM);
    uint32_t blockSize = B_DIM;
    uint32_t * tmp;

    while (inlen > 1)
    {
        reduceNonZero(data, inlen, aux, gridSize, blockSize);

        inlen = gridSize;

        if (inlen < 64)
        {
            blockSize = ceilToPower((inlen + 1) >> 1);
        }

        gridSize = 1 + (inlen - 1) / (2 * blockSize);

        tmp = data;
        data = aux;
        aux = tmp;
    }

    CUDA_CALL(cudaMemcpy(
        (void *)&res, (void *)data, sizeof(uint32_t), cudaMemcpyDeviceToHost
    ));

    return res;
}

// reduction.cu
