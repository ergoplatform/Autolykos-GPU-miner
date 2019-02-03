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
    // host allocation
    blake2b_ctx * ctx_h = (blake2b_ctx *)malloc(sizeof(blake2b_ctx));
    // 256 bits
    uint32_t * mes_h = (uint32_t *)calloc(8, sizeof(uint32_t)); 
    // L_SIZE * 256 bits
    //uint32_t * res_h = (uint32_t *)malloc(L_SIZE * 8 * sizeof(uint32_t)); 

    // device allocation
    uint32_t * data_d;
    CUDA_CALL(cudaMalloc(&data_d, BDIM * sizeof(uint32_t)));
    // L_SIZE * 256 bits
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc(&res_d, L_SIZE * 8 * sizeof(uint32_t)));

    int ind = -1;

    // intialize random generator
    curandGenerator_t gen;
    // L_SIZE * 256 bits
    uint32_t * non_d;
    initRand(&gen, &non_d);

    // secret key
    //>>>genKey();
    CUDA_CALL(cudaMemcpy(
        data_d, sk_h, KEY_LEN * sizeof(uint8_t), cudaMemcpyHostToDevice
    ));

    while (1)
    {
        if (ind >= 0)
        {
            // one time secret key
            //>>>genKey();

            //>>>hash();
        }

        // generate nonces
        CURAND_CALL(curandGenerate(gen, non_d, L_SIZE * 8));

        // calculate unfinalized hash of message
        partialHash(ctx_h, sk_h, mes_h, 32);

        CUDA_CALL(cudaMemcpy(
            data_d + 8, ctx_h, sizeof(blake2b_ctx), cudaMemcpyHostToDevice
        ));

        // calculate hashes
        blockMining<<<GDIM, BDIM>>>(ctx_d, hash_d, non_d, res_d);

        //>>>ind = findSolution(res);
    }

    CURAND_CALL(curandDestroyGenerator(gen));
    CUDA_CALL(cudaFree(non));
    CUDA_CALL(cudaFree(data_d));
    free(ctx_h);

    return 0;
}

