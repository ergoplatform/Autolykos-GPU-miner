#ifndef REDUCTION_H
#define REDUCTION_H

#include "autolykos.h"

////////////////////////////////////////////////////////////////////////////////
//  Reduction
////////////////////////////////////////////////////////////////////////////////
uint32_t ceilToPower(
    uint32_t x
);

// find non zero item in warp
template <uint32_t blockSize>
__device__ void warpNonZero(
    volatile uint32_t * sdata,
    uint32_t tid
);

// find non zero item in block
template <uint32_t blockSize>
__global__ void blockNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out
);

// find non zero item in each block of array
void reduceNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out,
    uint32_t gridSize,
    uint32_t blockSize
);

// find non zero item in array
uint32_t findNonZero(
    uint32_t * data,
    uint32_t * aux
);

#endif // REDUCTION_H
