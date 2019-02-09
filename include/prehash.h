#ifndef PREHASH_H
#define PREHASH_H

#include "definitions.h"

////////////////////////////////////////////////////////////////////////////////
//  Prehash calculation
////////////////////////////////////////////////////////////////////////////////
// first iteration of hashes precalculation
__global__ void initPrehash(
    // data: pk || mes || w || x || sk
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid
);

// unfinalized hashes update
__global__ void updatePrehash(
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid
);

// hashes by secret key multiplication mod q 
__global__ void finalizePrehash(
    // data: pk || mes || w || x || sk
    const uint32_t * data,
    // hashes
    uint32_t * hash
);

// precalculate hashes
int prehash(
    // data: pk || mes || w || x || sk
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid
);

#endif // PREHASH_H
