#ifndef PREHASH_H
#define PREHASH_H

#include "definitions.h"

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

// precalculate hashes
int prehash(
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    // indices of out of bounds hashes
    uint32_t * indices
);

#endif // PREHASH_H
