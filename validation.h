#ifndef VALIDATION_H
#define VALIDATION_H

#include "autolykos.h"

////////////////////////////////////////////////////////////////////////////////
//  Validation
////////////////////////////////////////////////////////////////////////////////
// unfinalized hash of message
void initMining(
    // context
    blake2b_ctx * ctx,
    // optional secret key
    const void * key,
    // message
    const void * mes,
    uint32_t meslen
);

// block mining iteration
__global__ void blockMining(
    // hash constants & secret key
    const uint32_t * data,
    // pregenerated nonces
    const uint32_t * non,
    // precalculated hashes
    const uint32_t * hash,
    // results
    uint32_t * res,
    uint32_t * unfinalized
);

#endif // VALIDATION_H
