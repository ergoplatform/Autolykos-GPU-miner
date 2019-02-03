#include "autolykos.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cuda.h>
#include <curand.h>

#define CUDA_CALL(x) do { if((x) != cudaSuccess) { \
printf("Error at %s:%d\n",__FILE__,__LINE__);      \
return EXIT_FAILURE;}} while (0)

#define CURAND_CALL(x) do { if((x) != CURAND_STATUS_SUCCESS) { \
printf("Error at %s:%d\n",__FILE__,__LINE__);                  \
return EXIT_FAILURE;}} while (0)

////////////////////////////////////////////////////////////////////////////////
//  Initialize random generator
////////////////////////////////////////////////////////////////////////////////
void initRand(
    curandGenerator_t * gen,
    uint32_t ** non
) {
    CURAND_CALL(curandCreateGenerator(gen, CURAND_RNG_PSEUDO_MTGP32));
    CUDA_CALL(cudaMalloc((void **)non, L_SIZE * 4 * sizeof(uint32_t)));

    time_t rawtime;
    time(&rawtime);
    CURAND_CALL(curandSetPseudoRandomGeneratorSeed(gen, (uint64_t)rawtime));

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Find solution of the puzzle
////////////////////////////////////////////////////////////////////////////////
//int findSolution(
//    uint32_t * res
//) {
//    int i = -1;
//
//    for (int r = 0; r < L_SIZE << 2; r += 4) 
//    {
//        if (
//            res[r + 3] == 0 || res[r + 2] == 0
//            || res[r + 1] == 0 || res[r]  <= B_SIZE)
//        {
//            i = r >> 2;
//            break;
//        }
//    }
//
//    return i;
//}

////////////////////////////////////////////////////////////////////////////////
//  Main cycle
////////////////////////////////////////////////////////////////////////////////
int main(int argc, char ** argv)
{
    curandGenerator_t gen;
    // L_SIZE * 256 bits
    uint32_t * non_d;
    initRand(&gen, &non_d);

    blake2b_ctx * ctx_h = (blake2b_ctx *)malloc(sizeof(blake2b_ctx));
    // 256 bits
    uint32_t * mes_h = (uint32_t *)calloc(8, sizeof(uint32_t)); 
    // L_SIZE * 256 bits
    uint32_t * res_h = (uint32_t *)malloc(L_SIZE * 4 * sizeof(uint32_t)); 

    blake2b_ctx * ctx_d;
    CUDA_CALL(cudaMalloc(&ctx_d, BDIM * sizeof(uint32_t)));
    // L_SIZE * 256 bits
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc(&res_d, L_SIZE * 4 * sizeof(uint32_t)));

    int ind = -1;

    // secret key
    //>>>genKey();

    while (1)
    {
        // one time secret key
        //>>>genKey()
        ;

        if (ind >= 0)
        {
            //>>>hash();
        }

        // generate nonces
        CURAND_CALL(curandGenerate(gen, non_d, L_SIZE));

        // calculate unfinalized hash of message
        partialHash(ctx_h, NULL, mes_h, 32);

        CUDA_CALL(cudaMemcpy(
            ctx_d, ctx_h, sizeof(blake2b_ctx), cudaMemcpyHostToDevice
        ));

        // calculate hashes
        blockMining<<<GDIM, BDIM>>>(ctx_d, non_d, res_d);

        //>>>ind = findSolution(res);
    }

    CURAND_CALL(curandDestroyGenerator(gen));
    CUDA_CALL(cudaFree(non));
    CUDA_CALL(cudaFree(ctx_d));
    free(ctx_h);

    return 0;
}

