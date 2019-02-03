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
    const uint64_t blake2b_iv[8] = {
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
    };

    const uint8_t sigma[12 * 16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
    };

    // host allocation
    blake2b_ctx * ctx_h = (blake2b_ctx *)malloc(sizeof(blake2b_ctx));
    // 256 bits
    uint32_t mes_h[8] = {
        0, 0, 0, 0, 0, 0, 0, 0
    }; 

    // L_SIZE * 256 bits
    //uint32_t * res_h = (uint32_t *)malloc(L_SIZE * 8 * sizeof(uint32_t)); 

    // device allocation
    void * data_d;
    CUDA_CALL(cudaMalloc((void **)&data_d, 2 * BDIM * sizeof(uint32_t)));
    CUDA_CALL(cudaMemcpy(
        data_d, (void *)blake2b_iv, 8 * sizeof(uint64_t), cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemcpy(
        (void *)((uint32_t *)data_d + 16), (void *)sigma, 12 * 16 * sizeof(uint8_t), cudaMemcpyHostToDevice
    ));

    // L_SIZE * 256 bits
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc((void **)&res_d, L_SIZE * 8 * sizeof(uint32_t)));

    int ind = -1;

    // intialize random generator
    curandGenerator_t gen;
    // L_SIZE * 256 bits
    uint32_t * non_d;
    initRand(&gen, &non_d);

    // secret key
    //>>>genKey();
    CUDA_CALL(cudaMemcpy(
        (void *)((uint32_t *)data_d + 64), sk_h, KEY_LEN * sizeof(uint8_t),
        cudaMemcpyHostToDevice
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
            (void *)((uint32_t *)data_d + 64 + KEY_LEN / sizeof(uint32_t)),
            (void *)ctx_h, sizeof(blake2b_ctx), cudaMemcpyHostToDevice
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

