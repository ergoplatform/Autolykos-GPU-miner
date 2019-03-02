// autolykos.cu

/*******************************************************************************

    AUTOLYKOS -- Autolukos puzzle cycle

*******************************************************************************/

#include "../include/prehash.h"
#include "../include/mining.h"
#include "../include/reduction.h"
#include "../include/compaction.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <inttypes.h>
#include <cuda.h>
#include <curand.h>

////////////////////////////////////////////////////////////////////////////////
//  Read program input from file
////////////////////////////////////////////////////////////////////////////////
int readInput(
    char * filename,
    void * bound,
    void * mes,
    void * sk,
    void * pk,
    void * x,
    void * w
) {
    FILE * in = fopen(filename, "r");

    int status;

#define SCAN_TO_LITTLE_ENDIAN(x)                                        \
for (int i = 0; i < NUM_SIZE_32 >> 1; ++i)                              \
{                                                                       \
    status = fscanf(                                                    \
        in, "%"SCNx64"\n", (uint64_t *)(x) + (NUM_SIZE_32 >> 1) - i - 1 \
    );                                                                  \
}

#define SCAN_TO_BIG_ENDIAN(x)                                \
for (int i = 0; i < NUM_SIZE_32 >> 1; ++i)                   \
{                                                            \
    status = fscanf(in, "%"SCNx64"\n", (uint64_t *)(x) + i); \
                                                             \
    INPLACE_REVERSE_ENDIAN((uint64_t *)(x) + i);             \
}

    SCAN_TO_LITTLE_ENDIAN(bound);
    SCAN_TO_BIG_ENDIAN(mes);
    SCAN_TO_LITTLE_ENDIAN(sk);

    status = fscanf(in, "%"SCNx8"\n", (uint8_t *)pk);
    SCAN_TO_BIG_ENDIAN((uint8_t *)pk + 1);

    SCAN_TO_LITTLE_ENDIAN(x);

    status = fscanf(in, "%"SCNx8"\n", (uint8_t *)w);
    SCAN_TO_BIG_ENDIAN((uint8_t *)w + 1);

#undef SCAN_TO_BIG_ENDIAN
#undef SCAN_TO_LITTLE_ENDIAN

    fclose(in);

    return status;
}

////////////////////////////////////////////////////////////////////////////////
//  Generate consequtive nonces
////////////////////////////////////////////////////////////////////////////////
__global__ void generate(
    uint64_t * arr,
    uint32_t len,
    uint64_t base
) {
    uint32_t tid = threadIdx.x + blockDim.x * blockIdx.x;

    uint64_t nonce = base + tid;

    INPLACE_REVERSE_ENDIAN(&nonce);

    if (tid < len) arr[tid] = nonce;

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Main cycle
////////////////////////////////////////////////////////////////////////////////
int main(
    int argc, char ** argv
) {
    int deviceCount;
    cudaGetDeviceCount(&deviceCount);

    if (!deviceCount)
    {
        printf("ABORT: GPU devices did not recognised.");

        return 1;
    }

    //====================================================================//
    //  Host memory
    //====================================================================//
    // hash context
    // (212 + 4) bytes
    blake2b_ctx ctx_h;

    uint32_t bound_h[NUM_SIZE_32];
    uint32_t mes_h[NUM_SIZE_32];
    uint32_t sk_h[NUM_SIZE_32];
    uint8_t pk_h[PK_SIZE_8];
    uint32_t x_h[NUM_SIZE_32];
    uint8_t w_h[PK_SIZE_8];

    if (argc == 1)
    {
        printf("Please, specify the input filename\n");
        fflush(stdout);

        return -1;
    }

    readInput(argv[1], bound_h, mes_h, sk_h, pk_h, x_h, w_h);

    //====================================================================//
    //  Device memory
    //====================================================================//
    // boundary for puzzle
    uint32_t * bound_d;
    CUDA_CALL(cudaMalloc((void **)&bound_d, NUM_SIZE_8));

    // nonces
    // H_LEN * L_LEN * NONCE_SIZE_8 bytes // 32 MB
    uint32_t * nonce_d;
    CUDA_CALL(cudaMalloc((void **)&nonce_d, H_LEN * L_LEN * NONCE_SIZE_8));

    // data: pk || mes || w || padding || x || sk || ctx
    // (2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) bytes // ~0 MB
    uint32_t * data_d;
    CUDA_CALL(cudaMalloc((void **)&data_d, (NUM_SIZE_8 + B_DIM) * 4));

    // precalculated hashes
    // N_LEN * NUM_SIZE_8 bytes // 2 GB
    uint32_t * hash_d;
    CUDA_CALL(cudaMalloc((void **)&hash_d, (uint32_t)N_LEN * NUM_SIZE_8));

    // indices of unfinalized hashes
    // (H_LEN * N_LEN * 8 + 4) bytes // ~512 MB
    uint32_t * indices_d;
    CUDA_CALL(cudaMalloc((void **)&indices_d, H_LEN * N_LEN * 8 + 4));

    // potential solutions of puzzle
    // H_LEN * L_LEN * 4 * 8 bytes // 16 * 8 MB
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc((void **)&res_d, H_LEN * L_LEN * NUM_SIZE_8));

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
    // bound
    CUDA_CALL(cudaMemcpy(
        (void *)bound_d, (void *)bound_h, NUM_SIZE_8, cudaMemcpyHostToDevice
    ));

    // public key
    CUDA_CALL(cudaMemcpy(
        (void *)data_d, (void *)pk_h, PK_SIZE_8, cudaMemcpyHostToDevice
    ));

    // message
    CUDA_CALL(cudaMemcpy(
        (void *)((uint8_t *)data_d + PK_SIZE_8), (void *)mes_h, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    // secret key
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + PK2_SIZE_32 + 2 * NUM_SIZE_32), (void *)sk_h,
        NUM_SIZE_8, cudaMemcpyHostToDevice
    ));

    //====================================================================//
    //  Autolykos puzzle cycle
    //====================================================================//
    uint32_t ind = 0;
    uint32_t is_first = 1;
    int i;
    struct timeval t1, t2, t3;
    uint64_t base = 0;

    for (i = 0; !ind && i < 1; ++i)
    {
        gettimeofday(&t1, 0);

        // on obtaining solution
        if (is_first)
        {
            // one time secret key: host -> device
            CUDA_CALL(cudaMemcpy(
                (void *)(data_d + PK2_SIZE_32 + NUM_SIZE_32), (void *)x_h,
                NUM_SIZE_8, cudaMemcpyHostToDevice
            ));

            // one time public key: host -> device
            CUDA_CALL(cudaMemcpy(
                (void *)((uint8_t *)data_d + PK_SIZE_8 + NUM_SIZE_8),
                (void *)w_h, PK_SIZE_8, cudaMemcpyHostToDevice
            ));

            // precalculate hashes
            prehash(data_d, hash_d, indices_d);

            is_first = 0;
        }

        CUDA_CALL(cudaDeviceSynchronize());
        gettimeofday(&t2, 0);
        /// prehash /// break;

        // generate nonces
        /// original /// CURAND_CALL(curandGenerate(gen, nonce_d, H_LEN * L_LEN * NONCE_SIZE_8));
        generate<<<1 + (H_LEN * L_LEN - 1) / B_DIM, B_DIM>>>(
            (uint64_t *)nonce_d, N_LEN, base
        );
        base += H_LEN * L_LEN;

        // calculate unfinalized hash of message
        initMining(&ctx_h, mes_h, NUM_SIZE_8);

        // context: host -> device
        CUDA_CALL(cudaMemcpy(
            (void *)(data_d + PK2_SIZE_32 + 3 * NUM_SIZE_32), (void *)&ctx_h,
            sizeof(blake2b_ctx), cudaMemcpyHostToDevice
        ));

        // calculate solution candidates
        blockMining<<<1 + (L_LEN - 1) / B_DIM, B_DIM>>>(
            bound_d, data_d, nonce_d, hash_d, res_d, indices_d
        );

        // try to find solution
        ind = findNonZero(indices_d, indices_d + H_LEN * L_LEN, H_LEN * L_LEN);
    }

    cudaDeviceSynchronize();
    gettimeofday(&t3, 0);

    //====================================================================//
    //  Time evaluation
    //====================================================================//
    double time
        = (1000000. * (t2.tv_sec - t1.tv_sec) + t2.tv_usec - t1.tv_usec)
        / 1000000.0;
    printf("Prehash time: %.5f (s) \n", time);

    time = (1000000. * (t3.tv_sec - t2.tv_sec) + t3.tv_usec - t2.tv_usec)
        / 1000000.0;
    printf("Mining time: %.5f (s) \n", time);

    fflush(stdout);

    //====================================================================//
    //  [DEBUG] Result with index
    //====================================================================//
    uint32_t * res_h = (uint32_t *)malloc(H_LEN * L_LEN * NUM_SIZE_8);

    CUDA_CALL(cudaMemcpy(
        (void *)res_h, (void *)res_d, H_LEN * L_LEN * NUM_SIZE_8,
        cudaMemcpyDeviceToHost
    ));

    uint32_t * nonce_h = (uint32_t *)malloc(H_LEN * L_LEN * NONCE_SIZE_8);

    CUDA_CALL(cudaMemcpy(
        (void *)nonce_h, (void *)nonce_d, H_LEN * L_LEN * NONCE_SIZE_8,
        cudaMemcpyDeviceToHost
    ));

    if (ind)
    {
        printf("iteration = %d, index = %d\n", i - 1, ind - 1);

        printf(
            "m     = 0x%016lX %016lX %016lX %016lX\n",
            ((uint64_t *)mes_h)[3], ((uint64_t *)mes_h)[2],
            ((uint64_t *)mes_h)[1], ((uint64_t *)mes_h)[0]
        );

        printf(
            "pk    = 0x%02lX %016lX %016lX %016lX %016lX\n",
            ((uint8_t *)pk_h)[0],
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)pk_h + 1)) + 0),
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)pk_h + 1)) + 1),
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)pk_h + 1)) + 2),
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)pk_h + 1)) + 3)
        );

        printf(
            "w     = 0x%02lX %016lX %016lX %016lX %016lX\n",
            ((uint8_t *)w_h)[0],
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w_h + 1)) + 0),
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w_h + 1)) + 1),
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w_h + 1)) + 2),
            REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w_h + 1)) + 3)
        );

        printf(
            "nonce = 0x%016lX\n",
            REVERSE_ENDIAN(((uint64_t *)nonce_h) + ind - 1)
        );

        printf(
            "d     = 0x%016lX %016lX %016lX %016lX\n",
            ((uint64_t *)res_h)[(ind - 1) * 4 + 3],
            ((uint64_t *)res_h)[(ind - 1) * 4 + 2],
            ((uint64_t *)res_h)[(ind - 1) * 4 + 1],
            ((uint64_t *)res_h)[(ind - 1) * 4]
        );

        fflush(stdout);
    }

    free(res_h);
    free(nonce_h);

    //====================================================================//
    //  Free device memory
    //====================================================================//
    /// original /// CURAND_CALL(curandDestroyGenerator(gen));
    CUDA_CALL(cudaFree(bound_d));
    CUDA_CALL(cudaFree(nonce_d));
    CUDA_CALL(cudaFree(hash_d));
    CUDA_CALL(cudaFree(data_d));
    CUDA_CALL(cudaFree(indices_d));
    CUDA_CALL(cudaFree(res_d));

    return 0;
}

// autolykos.cu
