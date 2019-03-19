#ifndef MINING_H
#define MINING_H

/*******************************************************************************

    MINING -- Autolykos parallel blockMining procedure

*******************************************************************************/

#include "definitions.h"

// unfinalized hash of message
void InitMining(
    // context
    blake2b_ctx * ctx,
    // message
    const uint32_t * mes,
    // message length in bytes
    const uint32_t meslen
);

// block mining iteration
__global__ void BlockMining(
    // boundary for puzzle
    const uint32_t * bound,
    // data: pk || mes || w || padding || x || sk || ctx
    const uint32_t * data,
    // pregenerated nonces
    const uint32_t * non,
    // precalculated hashes
    const uint32_t * hash,
    // results
    uint32_t * res,
    // indices of valid solutions
    uint32_t * valid
);

#endif // MINING_H
