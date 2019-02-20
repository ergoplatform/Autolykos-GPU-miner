#ifndef VALIDATION_H
#define VALIDATION_H

#include "definitions.h"

////////////////////////////////////////////////////////////////////////////////
//  Validation
////////////////////////////////////////////////////////////////////////////////
// unfinalized hash of message
void initMining(
    // context
    blake2b_ctx * ctx,
    // message
    const uint32_t * mes,
    const uint32_t meslen
);

// block mining iteration
__global__ void blockMining(
    // data: pk || mes || w || x || sk || ctx
    const uint32_t * data,
    // pregenerated nonces
    const uint32_t * non,
    // precalculated hashes
    const uint32_t * hash,
    // results
    uint32_t * res,
    uint32_t * valid
);

#endif // VALIDATION_H
