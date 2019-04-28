#ifndef REDUCTION_H
#define REDUCTION_H

/*******************************************************************************

    REDUCTION -- Identification of Autolykos puzzle solution 

*******************************************************************************/

#include "definitions.h"

// find smallest power of two not lesser then given number
uint32_t CeilToPower(uint32_t x);

// find non zero item in block
template<uint32_t blockSize>
__global__ void BlockNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out
);

// sum all elements in a block
template<uint32_t blockSize>
__global__ void BlockSum(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out
);

// find non zero item in each block of array
void ReduceNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out,
    uint32_t gridSize,
    uint32_t blockSize
);

// find sum of all elements in each block of array
void ReduceSum(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out,
    uint32_t gridSize,
    uint32_t blockSize
);

// find non zero item in array
uint32_t FindNonZero(
    uint32_t * data,
    uint32_t * aux,
    uint32_t inlen
);

// find sum of all elements in array
uint32_t FindSum(
    uint32_t * data,
    uint32_t * aux,
    uint32_t inlen
);

#endif // REDUCTION_H
