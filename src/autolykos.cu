// autolykos.cu

#include "../include/prehash.h"
#include "../include/validation.h"
#include "../include/reduction.h"
#include "../include/compaction.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <cuda.h>
#include <curand.h>

////////////////////////////////////////////////////////////////////////////////
//  Main cycle
////////////////////////////////////////////////////////////////////////////////
int main(int argc, char ** argv)
{
    //====================================================================//
    //  Host memory
    //====================================================================//
    uint32_t ind = 0;

    // hash context
    // (212 + 4) bytes
    blake2b_ctx ctx_h;

    // message stub
    // 8 * 32 bits = 32 bytes
    uint32_t mes_h[8] = {0, 0, 0, 0, 0, 0, 0, 0}; 

    //====================================================================//
    // secret key
    //>>>genSKey();
    uint32_t sk_h[8] = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2}; 

    // public key
    //>>>genPKey();
    uint32_t pk_h[8] = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 3, 4}; 

    // one time secret key
    //>>>genSKey();
    uint32_t x_h[8] = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 5, 6}; 

    // one time public key
    //>>>genPKey();
    uint32_t w_h[8] = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 8}; 

    //====================================================================//
    //  Device memory
    //====================================================================//
    // nonces
    // H_LEN * L_LEN * NON_BYTE_SIZE bytes // 32 MB
    uint32_t * non_d;
    CUDA_CALL(cudaMalloc((void **)&non_d, H_LEN * L_LEN * NON_BYTE_SIZE));

    // data: pk || mes || w || x || sk || ctx
    // (5 * NUM_BYTE_SIZE + 212 + 4) bytes // ~0 MB
    uint32_t * data_d;
    CUDA_CALL(cudaMalloc((void **)&data_d, (NUM_BYTE_SIZE + B_DIM) * 4));

    // precalculated hashes
    // N_LEN * NUM_BYTE_SIZE bytes // 2 GB
    uint32_t * hash_d;
    CUDA_CALL(cudaMalloc((void **)&hash_d, (uint32_t)N_LEN * NUM_BYTE_SIZE));

    // indices of unfinalized hashes
    // (H_LEN * N_LEN * 8 + 4) bytes // ~512 MB
    uint32_t * indices_d;
    CUDA_CALL(cudaMalloc((void **)&indices_d, (uint32_t)H_LEN * N_LEN * 8 + 4));

    // potential solutions of puzzle
    // H_LEN * L_LEN * 4 bytes // 16 MB
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc((void **)&res_d, (uint32_t)H_LEN * L_LEN * 4));

    //====================================================================//
    //  Random generator initialization
    //====================================================================//
    curandGenerator_t gen;
    CURAND_CALL(curandCreateGenerator(&gen, CURAND_RNG_PSEUDO_MTGP32));
    
    time_t rawtime;
    // get current time (ms)
    time(&rawtime);

    // set seed
    CURAND_CALL(curandSetPseudoRandomGeneratorSeed(gen, (uint64_t)rawtime));

    //====================================================================//
    //  Memory: Host -> Device
    //====================================================================//
    CUDA_CALL(cudaMemcpy(
        (void *)data_d, (void *)pk_h, NUM_BYTE_SIZE, cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + (NUM_BYTE_SIZE >> 2)), (void *)mes_h,
        NUM_BYTE_SIZE, cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + 2 * (NUM_BYTE_SIZE >> 2)), (void *)w_h,
        NUM_BYTE_SIZE, cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + 3 * (NUM_BYTE_SIZE >> 2)), (void *)x_h,
        NUM_BYTE_SIZE, cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + 4 * (NUM_BYTE_SIZE >> 2)), (void *)sk_h,
        NUM_BYTE_SIZE, cudaMemcpyHostToDevice
    ));

    //====================================================================//
    //  Autolykos puzzle cycle
    //====================================================================//
    uint32_t is_first = 1;
    int i;
    struct timeval t1, t2;

    for (i = 0; !ind && i < 18700; ++i) //>>>(1)
    {
        /// gettimeofday(&t1, 0);

        // on obtaining solution
        if (is_first)
        {
            //>>>genSKey();
            CUDA_CALL(cudaMemcpy(
                (void *)(data_d + 3 * (NUM_BYTE_SIZE >> 2)), (void *)x_h,
                NUM_BYTE_SIZE, cudaMemcpyHostToDevice
            ));
            //>>>genPKey();
            CUDA_CALL(cudaMemcpy(
                (void *)(data_d + 2 * (NUM_BYTE_SIZE >> 2)), (void *)w_h,
                NUM_BYTE_SIZE, cudaMemcpyHostToDevice
            ));

            prehash(data_d, hash_d, indices_d);

            gettimeofday(&t1, 0);

            is_first = 0;
        }

        /// CUDA_CALL(cudaThreadSynchronize());
        /// gettimeofday(&t2, 0);

        // generate nonces
        CURAND_CALL(curandGenerate(gen, non_d, H_LEN * L_LEN * NON_BYTE_SIZE));

        // calculate unfinalized hash of message
        initMining(&ctx_h, mes_h, NUM_BYTE_SIZE);

        // context: host -> device
        CUDA_CALL(cudaMemcpy(
            (void *)(data_d + 5 * (NUM_BYTE_SIZE >> 2)), (void *)&ctx_h,
            sizeof(blake2b_ctx), cudaMemcpyHostToDevice
        ));

        // calculate hashes
        blockMining<<<1 + (L_LEN - 1) / B_DIM, B_DIM>>>(
            data_d, non_d, hash_d, res_d, indices_d
        );

        // try to find solution
        ind = findNonZero(indices_d, indices_d + H_LEN * L_LEN * 4);
        // printf("%d ", ind);
        // fflush(stdout);
        // ind = 0;

        /// debug /// uint32_t * indices_h = (uint32_t *)malloc(H_LEN * L_LEN * 4);

        /// debug /// CUDA_CALL(cudaMemcpy(
        /// debug ///     (void *)indices_h, (void *)indices_d,
        /// debug ///     H_LEN * L_LEN * 4, cudaMemcpyDeviceToHost
        /// debug /// ));

        /// debug /// int k = 0;
        /// debug /// for (int i = 0; i < H_LEN * L_LEN; ++i)
        /// debug /// {
        /// debug ///     if (indices_h[i] > 0)
        /// debug ///     {
        /// debug ///         printf("%d\n", indices_h[i]);
        /// debug ///     }
        /// debug ///     else
        /// debug ///     {
        /// debug ///         ++k;
        /// debug ///     }
        /// debug /// }
        /// debug /// printf("%d %d\n", k, H_LEN * L_LEN);

        /// debug /// free(indices_h);
    }

    cudaThreadSynchronize();
    gettimeofday(&t2, 0);

    double time
        = (1000000. * (t2.tv_sec - t1.tv_sec) + t2.tv_usec - t1.tv_usec)
        / 1000000.0;
    printf("Time to generate: %.5f (s) \n", time);

    if (ind)
    {
        printf("ind = %d, i = %d\n", ind, i - 1);
        fflush(stdout);
    }

    //====================================================================//
    //  Free device memory
    //====================================================================//
    CURAND_CALL(curandDestroyGenerator(gen));
    CUDA_CALL(cudaFree(non_d));
    CUDA_CALL(cudaFree(hash_d));
    CUDA_CALL(cudaFree(data_d));
    CUDA_CALL(cudaFree(indices_d));
    CUDA_CALL(cudaFree(res_d));

    return 0;
}

// autolykos.cu
