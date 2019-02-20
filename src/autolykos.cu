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

__global__ void generate(
    uint64_t * arr,
    uint32_t len,
    uint64_t base
) {
    uint32_t tid = threadIdx.x + blockDim.x * blockIdx.x;

    if (tid < len) arr[tid] = base + tid;

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Main cycle
////////////////////////////////////////////////////////////////////////////////
int main(int argc, char ** argv)
{
    //====================================================================//
    //  Host memory
    //====================================================================//
    // hash context
    // (212 + 4) bytes
    blake2b_ctx ctx_h;

    // message stub
    // NUM_SIZE_8 bytes
    uint32_t mes_h[NUM_SIZE_32] = {0, 0, 0, 0, 0, 0, 0, 1}; 

    // secret key
    //>>>genSKey();
    uint32_t sk_h[NUM_SIZE_32] = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2}; 

    // public key
    //>>>genPKey();
    uint32_t pk_h[NUM_SIZE_32] = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 3, 4}; 

    // one time secret key
    //>>>genSKey();
    uint32_t x_h[NUM_SIZE_32] = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 5, 6}; 

    // one time public key
    //>>>genPKey();
    uint32_t w_h[NUM_SIZE_32] = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 8}; 

    //====================================================================//
    //  Device memory
    //====================================================================//
    // nonces
    // H_LEN * L_LEN * NONCE_SIZE_8 bytes // 32 MB
    uint32_t * non_d;
    CUDA_CALL(cudaMalloc((void **)&non_d, H_LEN * L_LEN * NONCE_SIZE_8));

    // data: pk || mes || w || x || sk || ctx
    // (5 * NUM_SIZE_8 + 212 + 4) bytes // ~0 MB
    uint32_t * data_d;
    CUDA_CALL(cudaMalloc((void **)&data_d, (NUM_SIZE_8 + B_DIM) * 4));

    // precalculated hashes
    // N_LEN * NUM_SIZE_8 bytes // 2 GB
    uint32_t * hash_d;
    CUDA_CALL(cudaMalloc((void **)&hash_d, (uint32_t)N_LEN * NUM_SIZE_8));

    /// debug /// uint32_t * hash_dd;
    /// debug /// CUDA_CALL(cudaMalloc((void **)&hash_dd, (uint32_t)N_LEN * NUM_SIZE_8));

    // indices of unfinalized hashes
    // (H_LEN * N_LEN * 8 + 4) bytes // ~512 MB
    uint32_t * indices_d;
    CUDA_CALL(cudaMalloc((void **)&indices_d, H_LEN * N_LEN * 8 + 4));

    /// original /// // potential solutions of puzzle
    /// original /// // H_LEN * L_LEN * 4 bytes // 16 MB
    /// original /// uint32_t * res_d;
    /// original /// CUDA_CALL(cudaMalloc((void **)&res_d, (uint32_t)H_LEN * L_LEN * 4));

    // potential solutions of puzzle
    // H_LEN * L_LEN * 4 * 8 bytes // 16 * 8 MB
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc((void **)&res_d, H_LEN * L_LEN * 4 * 8));

    //====================================================================//
    //  Random generator initialization
    //====================================================================//
    /// original /// curandGenerator_t gen;
    /// original /// CURAND_CALL(curandCreateGenerator(&gen, CURAND_RNG_PSEUDO_MTGP32));
    /// original /// 
    /// original /// time_t rawtime;
    /// original /// // get current time (ms)
    /// original /// time(&rawtime);

    /// original /// // set seed
    /// original /// CURAND_CALL(curandSetPseudoRandomGeneratorSeed(gen, (uint64_t)rawtime));

    //====================================================================//
    //  Memory: Host -> Device
    //====================================================================//
    CUDA_CALL(cudaMemcpy(
        (void *)data_d, (void *)pk_h, NUM_SIZE_8, cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + NUM_SIZE_32), (void *)mes_h, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + 2 * NUM_SIZE_32), (void *)w_h, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + 3 * NUM_SIZE_32), (void *)x_h, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + 4 * NUM_SIZE_32), (void *)sk_h, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    //====================================================================//
    //  Autolykos puzzle cycle
    //====================================================================//
    uint32_t ind = 0;
    uint32_t is_first = 1;
    int i;
    struct timeval t1, t2;
    uint64_t base = 0;

    for (i = 0; !ind && i < 24000; ++i) //>>>(1)
    {
        /// prehash /// gettimeofday(&t1, 0);

        // on obtaining solution
        if (is_first)
        {
            //>>>genSKey();
            CUDA_CALL(cudaMemcpy(
                (void *)(data_d + 3 * NUM_SIZE_32), (void *)x_h,
                NUM_SIZE_8, cudaMemcpyHostToDevice
            ));
            //>>>genPKey();
            CUDA_CALL(cudaMemcpy(
                (void *)(data_d + 2 * NUM_SIZE_32), (void *)w_h,
                NUM_SIZE_8, cudaMemcpyHostToDevice
            ));

            prehash(data_d, hash_d, indices_d);
            /// debug /// prehash(data_d, hash_dd, indices_d);

            is_first = 0;

            gettimeofday(&t1, 0);
        }

        /// prehash /// CUDA_CALL(cudaDeviceSynchronize());
        /// prehash /// gettimeofday(&t2, 0);
        /// prehash /// break;

        // generate nonces
        /// original /// CURAND_CALL(curandGenerate(gen, non_d, H_LEN * L_LEN * NONCE_SIZE_8));
        generate<<<1 + (H_LEN * L_LEN - 1) / B_DIM, B_DIM>>>(
            (uint64_t *)non_d, N_LEN, base
        );
        base += H_LEN * L_LEN;

        // calculate unfinalized hash of message
        initMining(&ctx_h, mes_h, NUM_SIZE_8);

        // context: host -> device
        CUDA_CALL(cudaMemcpy(
            (void *)(data_d + 5 * NUM_SIZE_32), (void *)&ctx_h,
            sizeof(blake2b_ctx), cudaMemcpyHostToDevice
        ));

        // calculate hashes
        blockMining<<<1 + (L_LEN - 1) / B_DIM, B_DIM>>>(
            data_d, non_d, hash_d, res_d, indices_d
        );

        // try to find solution
        ind = findNonZero(indices_d, indices_d + H_LEN * L_LEN);

        /// debug /// printf("%d ", ind);
        /// debug /// fflush(stdout);

        /// debug /// ind = 0;

        /// debug /// uint32_t * indices_h = (uint32_t *)malloc(H_LEN * L_LEN * 4);

        /// debug /// CUDA_CALL(cudaMemcpy(
        /// debug ///     (void *)indices_h, (void *)res_d,
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

    cudaDeviceSynchronize();
    gettimeofday(&t2, 0);

    //====================================================================//
    //  Time evaluation
    //====================================================================//
    double time
        = (1000000. * (t2.tv_sec - t1.tv_sec) + t2.tv_usec - t1.tv_usec)
        / 1000000.0;
    printf("Time to generate: %.5f (s) \n", time);

    //====================================================================//
    //  [DEBUG] Result in index
    //====================================================================//
    uint32_t * res_h = (uint32_t *)malloc(H_LEN * L_LEN * 4 * 8);

    CUDA_CALL(cudaMemcpy(
        (void *)res_h, (void *)res_d, H_LEN * L_LEN * 4 * 8,
        cudaMemcpyDeviceToHost
    ));

    /// debug /// uint32_t * res_h = (uint32_t *)malloc((uint32_t)N_LEN * NUM_SIZE_8);
    /// debug /// uint32_t * res_hh = (uint32_t *)malloc((uint32_t)N_LEN * NUM_SIZE_8);

    /// debug /// CUDA_CALL(cudaMemcpy(
    /// debug ///     (void *)res_h, (void *)hash_d, (uint32_t)N_LEN * NUM_SIZE_8,
    /// debug ///     cudaMemcpyDeviceToHost
    /// debug /// ));
    /// debug /// CUDA_CALL(cudaMemcpy(
    /// debug ///     (void *)res_hh, (void *)hash_dd, (uint32_t)N_LEN * NUM_SIZE_8,
    /// debug ///     cudaMemcpyDeviceToHost
    /// debug /// ));

    /// debug /// for (uint32_t i = 0; i < N_LEN * NUM_SIZE_32; ++i)
    /// debug /// {
    /// debug ///     if (res_h[i] != res_hh[i])
    /// debug ///         printf("ERROR");
    /// debug /// }

    if (ind)
    {
        printf("ind = %d, i = %d\n", ind - 1, i - 1);
        printf(
            "0x%016lX %016lX %016lX %016lX\n",
            ((uint64_t *)res_h)[(ind - 1) * 4 + 3],
            ((uint64_t *)res_h)[(ind - 1) * 4 + 2],
            ((uint64_t *)res_h)[(ind - 1) * 4 + 1],
            ((uint64_t *)res_h)[(ind - 1) * 4]
        );
        fflush(stdout);
    }

    /// debug /// for (int i = 0; i < H_LEN * L_LEN; ++i)
    /// debug /// {
    /// debug ///     printf("%d ", res_h[i]);
    /// debug /// }

    free(res_h);

    //====================================================================//
    //  Free device memory
    //====================================================================//
    /// original /// CURAND_CALL(curandDestroyGenerator(gen));
    CUDA_CALL(cudaFree(non_d));
    CUDA_CALL(cudaFree(hash_d));
    CUDA_CALL(cudaFree(data_d));
    CUDA_CALL(cudaFree(indices_d));
    CUDA_CALL(cudaFree(res_d));

    return 0;
}

// autolykos.cu
