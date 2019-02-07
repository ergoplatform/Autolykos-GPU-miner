// reductiontest.cu 

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <cuda.h>
#include <cuda_runtime.h>
#include <cooperative_groups.h>

#define N_LEN         0x4000000          // 2^26
#define G_DIM         0x4000
#define B_DIM         64                 // G_DIM * B_DIM = L_LEN

#define CUDA_CALL(x) do { if((x) != cudaSuccess) { \
printf("Error at %s:%d\n",__FILE__,__LINE__);      \
return EXIT_FAILURE;}} while (0)

namespace cg = cooperative_groups;

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
/// template <uint32_t blockSize>
/// __global__ void blockNonZero(
///     uint32_t * in,
///     uint32_t inlen,
///     uint32_t * out
/// ) {
///     uint32_t ind = 0;
///     uint32_t tid = threadIdx.x;
///     __shared__ uint32_t sdata[B_DIM];
/// 
///     cg::thread_block cta = cg::this_thread_block();
/// 
///     for (
///         uint32_t i = 2 * blockIdx.x * blockSize + tid;
///         i < inlen;
///         i += 2 * blockSize * gridDim.x
///     ) {
///         ind += !ind * in[i];
///         ind += !ind * !(i + blockSize >= inlen) * in[i + blockSize];
///     }
/// 
///     sdata[tid] = ind;
///     cg::sync(cta);
/// 
/// #if (__CUDA_ARCH__ >= 300)
///     if (tid < 32)
///     {
///         cg::coalesced_group active = cg::coalesced_threads();
/// 
///         // Fetch final intermediate sum from 2nd warp
///         if (blockSize >= 64) ind += !ind * sdata[tid + 32];
/// 
///         // Reduce final warp using shuffle
///         for (int offset = warpSize >> 1; offset > 0; offset >>= 1) 
///         {
///              ind += !ind * active.shfl_down(ind, offset);
///         }
///     }
/// #else
///     if (blockSize >= 64 && tid < 32)
///     {
///         sdata[tid] = ind = ind + !ind * sdata[tid + 32];
///     }
/// 
///     cg::sync(cta);
/// 
///     if (blockSize >= 32 && tid < 16)
///     {
///         sdata[tid] = ind = ind + !ind * sdata[tid + 16];
///     }
/// 
///     cg::sync(cta);
/// 
///     if (blockSize >= 16 && tid < 8)
///     {
///         sdata[tid] = ind = ind + !ind * sdata[tid +  8];
///     }
/// 
///     cg::sync(cta);
/// 
///     if (blockSize >= 8 && tid < 4)
///     {
///         sdata[tid] = ind = ind + !ind * sdata[tid +  4];
///     }
/// 
///     cg::sync(cta);
/// 
///     if (blockSize >= 4 && tid < 2)
///     {
///         sdata[tid] = ind = ind + !ind * sdata[tid +  2];
///     }
/// 
///     cg::sync(cta);
/// 
///     if (blockSize >= 2 && tid < 1)
///     {
///         ind = ind + !ind * sdata[tid +  1];
///     }
/// 
///     cg::sync(cta);
/// #endif
/// 
///     // write result for this block to global mem
///     if (tid == 0) out[blockIdx.x] = ind;
/// }

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
    uint32_t inlen = N_LEN;
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

int main(int argc, char ** argv)
{
    uint32_t arr_h[0x4000000];
    //clock_t time;

    for (int i = 0; i < 0x4000000; ++i)
    {
        arr_h[i] = 0;
    }

    for (int i = 13; i < 0x4000000; i += 7)
    {
        arr_h[(uint32_t)rand() % 0x4000000] = i;
    }

    uint32_t * in_d;
    uint32_t * out_d;

    CUDA_CALL(cudaMalloc((void **)&in_d, 0x4000000 * 4));
    CUDA_CALL(cudaMalloc((void **)&out_d, 0x4000000 * 2));

    CUDA_CALL(cudaMemcpy(
        (void *)in_d, arr_h, 0x4000000 * 4, cudaMemcpyHostToDevice
    ));

    printf("\n");

    struct timeval t1, t2;

    gettimeofday(&t1, 0);




    int r = findNonZero(in_d, out_d);
    cudaThreadSynchronize();
    printf("%d\n", r);

    gettimeofday(&t2, 0);

    double time = (1000000.0*(t2.tv_sec-t1.tv_sec) + t2.tv_usec-t1.tv_usec)/1000.0;
    printf("Time to generate:  %3.5f ms \n", time);

    for (int i = 0; i < 0x4000000; ++i)
    {
        if (arr_h[i] == r)
        {
            printf("OK\n", i);
            break;
        }
    }

    CUDA_CALL(cudaFree(in_d));
    CUDA_CALL(cudaFree(out_d));

    return 0;
}

// reductiontest.cu 
