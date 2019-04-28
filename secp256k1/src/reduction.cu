// reduction.cu

/*******************************************************************************

    REDUCTION -- Identification of Autolykos puzzle solution 

*******************************************************************************/

#include "../include/reduction.h"
#include <stdio.h>
#include <stdlib.h>
#include <cooperative_groups.h>
#include <cuda.h>
#include <cuda_runtime.h>

namespace cg = cooperative_groups;

////////////////////////////////////////////////////////////////////////////////
//  Find smallest power of two not lesser then given number
////////////////////////////////////////////////////////////////////////////////
uint32_t CeilToPower(uint32_t x)
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
//  Find non zero item in block
////////////////////////////////////////////////////////////////////////////////
template<uint32_t blockSize>
__global__ void BlockNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out
)
{
    uint32_t ind = 0;
    uint32_t tid = threadIdx.x;
    __shared__ uint32_t sdata[BLOCK_DIM];

    cg::thread_block cta = cg::this_thread_block();

    for (
        uint32_t i = 2 * blockIdx.x * blockSize + tid;
        i < inlen;
        i += 2 * blockSize * gridDim.x
    )
    {
        ind += !ind * in[i];
        ind += !ind * !(i + blockSize >= inlen) * in[i + blockSize];
    }

    sdata[tid] = ind;
    cg::sync(cta);

#if (__CUDA_ARCH__ >= 300)
    if (tid < 32)
    {
        cg::coalesced_group active = cg::coalesced_threads();

        if (blockSize >= 64) { ind += !ind * sdata[tid + 32]; }

        for (int offset = warpSize >> 1; offset > 0; offset >>= 1) 
        {
             ind += !ind * active.shfl_down(ind, offset);
        }
    }
#else
    if (blockSize >= 64 && tid < 32)
    {
        sdata[tid] = ind = ind + !ind * sdata[tid + 32];
    }

    cg::sync(cta);

    if (blockSize >= 32 && tid < 16)
    {
        sdata[tid] = ind = ind + !ind * sdata[tid + 16];
    }

    cg::sync(cta);

    if (blockSize >= 16 && tid < 8)
    {
        sdata[tid] = ind = ind + !ind * sdata[tid + 8];
    }

    cg::sync(cta);

    if (blockSize >= 8 && tid < 4)
    {
        sdata[tid] = ind = ind + !ind * sdata[tid + 4];
    }

    cg::sync(cta);

    if (blockSize >= 4 && tid < 2)
    {
        sdata[tid] = ind = ind + !ind * sdata[tid + 2];
    }

    cg::sync(cta);

    if (blockSize >= 2 && tid < 1) { ind += !ind * sdata[tid + 1]; }
    cg::sync(cta);
#endif

    if (!tid) { out[blockIdx.x] = ind; }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Sum all elements in a block
////////////////////////////////////////////////////////////////////////////////
template<uint32_t blockSize>
__global__ void BlockSum(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out
)
{
    uint32_t ind = 0;
    uint32_t tid = threadIdx.x;
    __shared__ uint32_t sdata[BLOCK_DIM];

    cg::thread_block cta = cg::this_thread_block();

    for (
        uint32_t i = 2 * blockIdx.x * blockSize + tid;
        i < inlen;
        i += 2 * blockSize * gridDim.x
    )
    {
        ind += 1 - !(in[i]);
        ind += !(i + blockSize >= inlen) * (1 - !(in[i + blockSize]));
    }

    sdata[tid] = ind;
    cg::sync(cta);

#if (__CUDA_ARCH__ >= 300)
    if (tid < 32)
    {
        cg::coalesced_group active = cg::coalesced_threads();

        if (blockSize >= 64) { ind += sdata[tid + 32]; }

        for (int offset = warpSize >> 1; offset > 0; offset >>= 1) 
        {
             ind += 1 - !(active.shfl_down(ind, offset));
        }
    }
#else
    if (blockSize >= 64 && tid < 32)
    {
        sdata[tid] = ind = ind + sdata[tid + 32];
    }

    cg::sync(cta);

    if (blockSize >= 32 && tid < 16)
    {
        sdata[tid] = ind = ind + sdata[tid + 16];
    }

    cg::sync(cta);

    if (blockSize >= 16 && tid < 8)
    {
        sdata[tid] = ind = ind + sdata[tid + 8];
    }

    cg::sync(cta);

    if (blockSize >= 8 && tid < 4)
    {
        sdata[tid] = ind = ind + sdata[tid + 4];
    }

    cg::sync(cta);

    if (blockSize >= 4 && tid < 2)
    {
        sdata[tid] = ind = ind + sdata[tid + 2];
    }

    cg::sync(cta);

    if (blockSize >= 2 && tid < 1) { ind += sdata[tid + 1]; }
    cg::sync(cta);
#endif

    if (!tid) { out[blockIdx.x] = ind; }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Find non zero item in each block of array
////////////////////////////////////////////////////////////////////////////////
void ReduceNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out,
    uint32_t gridSize,
    uint32_t blockSize
)
{
    switch (blockSize)
    {
        case 64:
            BlockNonZero<64><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 32:
            BlockNonZero<32><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 16:
            BlockNonZero<16><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 8:
            BlockNonZero<8><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 4:
            BlockNonZero<4><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 2:
            BlockNonZero<2><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 1:
            BlockNonZero<1><<<gridSize, blockSize>>>(in, inlen, out);
            break;
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Find sum of all elements in each block of array
////////////////////////////////////////////////////////////////////////////////
void ReduceSum(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out,
    uint32_t gridSize,
    uint32_t blockSize
)
{
    switch (blockSize)
    {
        case 64:
            BlockSum<64><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 32:
            BlockSum<32><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 16:
            BlockSum<16><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 8:
            BlockSum<8><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 4:
            BlockSum<4><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 2:
            BlockSum<2><<<gridSize, blockSize>>>(in, inlen, out);
            break;

        case 1:
            BlockSum<1><<<gridSize, blockSize>>>(in, inlen, out);
            break;
    }

    return;
}


////////////////////////////////////////////////////////////////////////////////
//  Find non zero item in array
////////////////////////////////////////////////////////////////////////////////
uint32_t FindNonZero(
    uint32_t * data,
    uint32_t * aux,
    uint32_t inlen
)
{
    uint32_t res;
    uint32_t blockSize = (BLOCK_DIM < 64)? CeilToPower(BLOCK_DIM): 64;
    uint32_t gridSize = 1 + (inlen - 1) / (blockSize << 1);
    uint32_t * tmp;

    while (inlen > 1)
    {
        ReduceNonZero(data, inlen, aux, gridSize, blockSize);

        inlen = gridSize;

        if (inlen < 64) { blockSize = CeilToPower((inlen + 1) >> 1); }

        gridSize = 1 + (inlen - 1) / (blockSize << 1);

        tmp = data;
        data = aux;
        aux = tmp;
    }

    CUDA_CALL(cudaMemcpy(
        (void *)&res, (void *)data, INDEX_SIZE_8, cudaMemcpyDeviceToHost
    ));

    return res;
}

////////////////////////////////////////////////////////////////////////////////
//  Find sum of all elements in array
////////////////////////////////////////////////////////////////////////////////
uint32_t FindSum(
    uint32_t * data,
    uint32_t * aux,
    uint32_t inlen
)
{
    uint32_t res;
    uint32_t blockSize = (BLOCK_DIM < 64)? CeilToPower(BLOCK_DIM): 64;
    uint32_t gridSize = 1 + (inlen - 1) / (blockSize << 1);
    uint32_t * tmp;

    while (inlen > 1)
    {
        ReduceSum(data, inlen, aux, gridSize, blockSize);

        inlen = gridSize;

        if (inlen < 64) { blockSize = CeilToPower((inlen + 1) >> 1); }

        gridSize = 1 + (inlen - 1) / (blockSize << 1);

        tmp = data;
        data = aux;
        aux = tmp;
    }

    CUDA_CALL(cudaMemcpy(
        &res, data, INDEX_SIZE_8, cudaMemcpyDeviceToHost
    ));

    return res;
}

// reduction.cu
