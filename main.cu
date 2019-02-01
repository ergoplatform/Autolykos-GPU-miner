#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cuda.h>
#include <curand.h>

#include "blake2b.h"
#include "autolykos.h"

// L = GS * BS
#define GS 15625
#define BS 64

#define CUDA_CALL(x) do { if((x) != cudaSuccess) {  \
printf("Error at %s:%d\n",__FILE__,__LINE__);       \
return EXIT_FAILURE;}} while(0)

#define CURAND_CALL(x) do { if((x) != CURAND_STATUS_SUCCESS) {  \
printf("Error at %s:%d\n",__FILE__,__LINE__);                   \
return EXIT_FAILURE;}} while(0)

void initRand(
    curandGenerator_t * gen,
    uint32_t ** non
) {
    CURAND_CALL(curandCreateGenerator(gen, CURAND_RNG_PSEUDO_MTGP32));
    CUDA_CALL(cudaMalloc((void **)non, L * sizeof(uint32_t)));

    time_t rawtime;
    time(&rawtime);
    CURAND_CALL(curandSetPseudoRandomGeneratorSeed(gen, (uint64_t)rawtime));

    return;
}

int main(int argc, char ** argv)
{
    curandGenerator_t gen;
    uint32_t * non;

    initRand(&gen, &non);

    blake2b_ctx * ctx;
    cudaMalloc(&ctx, L * sizeof(blake2b_ctx));

    while(1)
    {
        // 

        // generate nonces
        CURAND_CALL(curandGenerate(gen, non, L));

        // calculate hashes
        blockMining<<<GS, BS>>>(
            // context
            ctx,
            // optional secret key
            NULL, 0,
            // message
            in, 64,
            // pregenerated nonces
            non,
            // hashes
            out, 32
        );

        findSolution<<<GS, BS>>>(
        );
    }

    CURAND_CALL(curandDestroyGenerator(gen));
    CUDA_CALL(cudaFree(non));
    CUDA_CALL(cudaFree(ctx));

    return 0;
}

