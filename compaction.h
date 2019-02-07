#ifndef COMPACTION_H
#define COMPACTION_H

#include "autolykos.h"

// increment a counter in a warp
__device__ int warpInc(
    uint32_t * c
);

// compactify an array, omit all zeros
__global__ void compactify(
    const uint32_t * in,
    uint32_t inlen,
    uint32_t * out,
    uint32_t * c
);

#endif // COMPACTION_H
