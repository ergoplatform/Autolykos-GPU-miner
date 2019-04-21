#ifndef COMPACTION_H
#define COMPACTION_H

/*******************************************************************************

    COMPACTION -- Identification of hashes subject to rehash 

*******************************************************************************/

#include "definitions.h"

// increment a counter in a warp
__device__ uint32_t WarpInc(uint32_t * len);

// compactify an array, omit all zeros
__global__ void Compactify(
    const uint32_t * in,
    const uint32_t inlen,
    uint32_t * out,
    uint32_t * outlen
);

#endif // COMPACTION_H
