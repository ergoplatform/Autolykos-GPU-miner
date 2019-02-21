// compaction.cu

#include "../include/compaction.h"
#include <cuda.h>
#include <cuda_runtime.h>
#include <cooperative_groups.h>

namespace cg = cooperative_groups;

////////////////////////////////////////////////////////////////////////////////
//  Increment a counter in a warp
////////////////////////////////////////////////////////////////////////////////
__device__ uint32_t warpInc(
    uint32_t * len
) {
    uint32_t res = 0;
    cg::coalesced_group active = cg::coalesced_threads();

    if (!active.thread_rank()) res = atomicAdd(len, active.size());

    return active.shfl(res, 0) + active.thread_rank();
}

////////////////////////////////////////////////////////////////////////////////
//  Compactify an array, omit all zeros
////////////////////////////////////////////////////////////////////////////////
__global__ void compactify(
    const uint32_t * in,
    const uint32_t inlen,
    uint32_t * out,
    uint32_t * outlen
) {
    uint32_t tid = threadIdx.x + blockIdx.x * blockDim.x;

    for (int i = tid; i < inlen; i += gridDim.x * blockDim.x)
    {
        if (in[i]) out[warpInc(outlen)] = in[i];
    }
}

// compaction.cu
