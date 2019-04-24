// test.cu

/*******************************************************************************

    TEST -- hash functions test suite

*******************************************************************************/

//#include "../include/test.h"
#include "../include/compaction.h"
#include "../include/conversion.h"
#include "../include/cryptography.h"
#include "../include/definitions.h"
#include "../include/easylogging++.h"
#include "../include/jsmn.h"
#include "../include/mining.h"
#include "../include/prehash.h"
#include "../include/processing.h"
#include "../include/reduction.h"
#include "../include/request.h"
#include <ctype.h>
#include <cuda.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <io.h>
#define R_OK 4       
#define W_OK 2       
#define F_OK 0       
#define access _access
#else
#include <unistd.h>
#endif

INITIALIZE_EASYLOGGINGPP

using namespace std::chrono;

////////////////////////////////////////////////////////////////////////////////
//  Precalculate hashes
////////////////////////////////////////////////////////////////////////////////
int TestPrehash(
    const int keep,
    // data: pk || mes || w || padding || x || sk
    const uint32_t * data,
    // hashes
    uint32_t * hashes,
    // indices of invalid range hashes
    uint32_t * invalid
)
{
    uint32_t len = N_LEN;

    uint32_t * ind = invalid;
    uint32_t * comp = invalid + N_LEN;
    uint32_t * tmp;

    // put zero to new length 
    CUDA_CALL(cudaMemset((void *)(invalid + 2 * N_LEN), 0, INDEX_SIZE_8));

    // hash index, constant message and public key
    InitPrehash<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(data, hashes, ind);

    // determine indices of out of bounds hashes
    Compactify<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
        ind, len, comp, invalid + 2 * N_LEN
    );

    // determine the quantity of invalid hashes
    CUDA_CALL(cudaMemcpy(
        (void *)&len, (void *)(invalid + 2 * N_LEN), INDEX_SIZE_8,
        cudaMemcpyDeviceToHost
    ));

    tmp = ind;
    ind = comp;
    comp = tmp;

    while (len)
    {
        // put zero to new length 
        CUDA_CALL(cudaMemset((void *)(invalid + 2 * N_LEN), 0, INDEX_SIZE_8));

        // rehash out of bounds hashes
        UpdatePrehash<<<1 + (len - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            hashes, ind, len
        );

        // determine indices of out of bounds hashes
        Compactify<<<1 + (len - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            ind, len, comp, invalid + 2 * N_LEN
        );

        // determine the quantity of invalid hashes
        CUDA_CALL(cudaMemcpy(
            (void *)&len, (void *)(invalid + 2 * N_LEN), INDEX_SIZE_8,
            cudaMemcpyDeviceToHost
        ));

        tmp = ind;
        ind = comp;
        comp = tmp;
    }

    // multiply by secret key moq Q
    FinalPrehash<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(hashes);

    return EXIT_SUCCESS;
}

void TestAlgorithm(void);

////////////////////////////////////////////////////////////////////////////////
//  Main
////////////////////////////////////////////////////////////////////////////////
int main(int argc, char ** argv)
{
    START_EASYLOGGINGPP(argc, argv);

    el::Loggers::reconfigureAllLoggers(
        el::ConfigurationType::Format, "%datetime %level [%thread] %msg"
    );

    el::Helpers::setThreadName("main thread test");

    int deviceCount;

    if (cudaGetDeviceCount(&deviceCount) != cudaSuccess)
    {
        LOG(ERROR) << "Error checking GPU";
        return EXIT_FAILURE;
    }

    /// LOG(INFO) << "Using " << deviceCount << " GPU devices";

    /// std::vector<std::thread> miners(deviceCount);

    /// for (int d = 0; d < deviceCount; ++d)
    /// {
    ///     miners[d] = std::thread(MinerThread, d, &info);
    /// }

    /// for (int d = 0; d < deviceCount; ++d) { miners[d].join(); };

    TestAlgorithm();

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Test algorithm
////////////////////////////////////////////////////////////////////////////////
void TestAlgorithm(void)
{
    //========================================================================//
    //  Host memory allocation
    //========================================================================//
    // hash context
    // (212 + 4) bytes
    ctx_t ctx_h;

    // autolykos variables
    uint8_t bound_h[NUM_SIZE_8];
    uint8_t mes_h[NUM_SIZE_8];
    uint8_t sk_h[NUM_SIZE_8];
    uint8_t pk_h[PK_SIZE_8];
    uint8_t x_h[NUM_SIZE_8];
    uint8_t w_h[PK_SIZE_8];

    // cryptography variables
    char skstr[NUM_SIZE_4];
    char pkstr[PK_SIZE_4 + 1];

    //========================================================================//
    //  Set test info
    //========================================================================//
    char seed[256] = "Va'esse deireadh aep eigean, va'esse eigh faidh'ar";

    /// LOG(INFO) << "Seed:\n" << seed;

    // generate secret key from seed
    GenerateSecKey(seed, 50, sk_h, skstr);

    // generate public key from secret key
    GeneratePublicKey(skstr, pkstr, pk_h);

    char logstr[1000];
    
    /// sprintf(
    ///     logstr, "Generated public key:\n"
    ///     "   pk = 0x%02lX %016lX %016lX %016lX %016lX",
    ///     pk_h[0],
    ///     REVERSE_ENDIAN((uint64_t *)(pk_h + 1) + 0),
    ///     REVERSE_ENDIAN((uint64_t *)(pk_h + 1) + 1),
    ///     REVERSE_ENDIAN((uint64_t *)(pk_h + 1) + 2),
    ///     REVERSE_ENDIAN((uint64_t *)(pk_h + 1) + 3)
    /// );

    /// LOG(INFO) << logstr;

    ((uint64_t *)bound_h)[0] = 0xFFFFFFFFFFFFFFFF;
    ((uint64_t *)bound_h)[1] = 0xFFFFFFFFFFFFFFFF;
    ((uint64_t *)bound_h)[2] = 0xFFFFFFFFFFFFFFFF;
    ((uint64_t *)bound_h)[3] = 0x00000FFFFFFFFFFF;

    /// sprintf(
    ///     logstr, "\n   bound = 0x%016lX %016lX %016lX %016lX",
    ///     ((uint64_t *)bound_h)[3], ((uint64_t *)bound_h)[2],
    ///     ((uint64_t *)bound_h)[1], ((uint64_t *)bound_h)[0]
    /// );

    /// LOG(INFO) << logstr;

    ((uint64_t *)mes_h)[0] = 1;
    ((uint64_t *)mes_h)[1] = 0;
    ((uint64_t *)mes_h)[2] = 0;
    ((uint64_t *)mes_h)[3] = 0;

    /// sprintf(
    ///     logstr, "\n     mes = 0x%016lX %016lX %016lX %016lX",
    ///     ((uint64_t *)mes_h)[3], ((uint64_t *)mes_h)[2],
    ///     ((uint64_t *)mes_h)[1], ((uint64_t *)mes_h)[0]
    /// );

    /// LOG(INFO) << logstr;

    //========================================================================//
    //  Device memory allocation
    //========================================================================//
    // boundary for puzzle
    // ~0 MiB
    uint32_t * bound_d;
    CUDA_CALL(cudaMalloc((void **)&bound_d, NUM_SIZE_8 + DATA_SIZE_8));

    // data: pk || mes || w || padding || x || sk || ctx
    // (2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) bytes // ~0 MiB
    uint32_t * data_d = bound_d + NUM_SIZE_32;

    // precalculated hashes
    // N_LEN * NUM_SIZE_8 bytes // 2 GiB
    uint32_t * hashes_d;
    CUDA_CALL(cudaMalloc((void **)&hashes_d, (uint32_t)N_LEN * NUM_SIZE_8));

    // WORKSPACE_SIZE_8 bytes // Depends on defines, now ~512 MiB
    // potential solutions of puzzle
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc((void **)&res_d, WORKSPACE_SIZE_8));

    // indices of unfinalized hashes
    uint32_t * indices_d = res_d + NONCES_PER_ITER * NUM_SIZE_32;

    //========================================================================//
    //  Key-pair transfer form host to device
    //========================================================================//
    // copy public key
    CUDA_CALL(cudaMemcpy(
        (void *)data_d, (void *)pk_h, PK_SIZE_8, cudaMemcpyHostToDevice
    ));

    // copy secret key
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + COUPLED_PK_SIZE_32 + 2 * NUM_SIZE_32), (void *)sk_h,
        NUM_SIZE_8, cudaMemcpyHostToDevice
    ));

    //========================================================================//
    //  Test solutions
    //========================================================================//
    uint64_t base = 0;
    uint64_t nonce;

    /// sprintf(seed, "%d", 0);
    /// LOG(INFO) << "One-time secret key seed: " << seed;

    // generate secret key from seed
    GenerateSecKey(seed, 1, x_h, skstr);

    // generate public key from secret key
    GeneratePublicKey(skstr, pkstr, w_h);
    
    /// sprintf(
    ///     logstr, "Generated one-time public key:\n"
    ///     "   pk = 0x%02lX %016lX %016lX %016lX %016lX",
    ///     w_h[0],
    ///     REVERSE_ENDIAN((uint64_t *)(w_h + 1) + 0),
    ///     REVERSE_ENDIAN((uint64_t *)(w_h + 1) + 1),
    ///     REVERSE_ENDIAN((uint64_t *)(w_h + 1) + 2),
    ///     REVERSE_ENDIAN((uint64_t *)(w_h + 1) + 3)
    /// );

    /// LOG(INFO) << logstr;

    // copy boundary
    CUDA_CALL(cudaMemcpy(
        (void *)bound_d, (void *)bound_h, NUM_SIZE_8, cudaMemcpyHostToDevice
    ));

    // copy message
    CUDA_CALL(cudaMemcpy(
        (void *)((uint8_t *)data_d + PK_SIZE_8), (void *)mes_h, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    // copy one time secret key
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + COUPLED_PK_SIZE_32 + NUM_SIZE_32), (void *)x_h,
        NUM_SIZE_8, cudaMemcpyHostToDevice
    ));

    // copy one time public key
    CUDA_CALL(cudaMemcpy(
        (void *)((uint8_t *)data_d + PK_SIZE_8 + NUM_SIZE_8), (void *)w_h,
        PK_SIZE_8, cudaMemcpyHostToDevice
    ));

    Prehash(0, data_d, NULL, hashes_d, res_d);
    CUDA_CALL(cudaDeviceSynchronize());

    // calculate unfinalized hash of message
    InitMining(&ctx_h, (uint32_t *)mes_h, NUM_SIZE_8);

    // copy context
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + COUPLED_PK_SIZE_32 + 3 * NUM_SIZE_32), (void *)&ctx_h,
        sizeof(ctx_t), cudaMemcpyHostToDevice
    ));

    // calculate solution candidates
    BlockMining<<<1 + (THREADS_PER_ITER - 1) / BLOCK_DIM, BLOCK_DIM>>>(
        bound_d, data_d, base, hashes_d, res_d, indices_d
    );

    /// // copy indices to host
    /// uint32_t indices_h[NONCES_PER_ITER];
    /// CUDA_CALL(cudaMemcpy(
    ///     (void *)indices_h, (void *)indices_d, NONCES_PER_ITER * INDEX_SIZE_8,
    ///     cudaMemcpyDeviceToHost
    /// ));

    /// // copy results to host
    /// uint32_t res_h[NONCES_PER_ITER * NUM_SIZE_32];
    /// CUDA_CALL(cudaMemcpy(
    ///     (void *)res_h, (void *)res_d, NONCES_PER_ITER * NUM_SIZE_8,
    ///     cudaMemcpyDeviceToHost
    /// ));

    uint32_t indices[3] = { 0x3381BD, 0x376C26, 0x3D5B84 };

    uint64_t res[3 * NUM_SIZE_64] = {
        0xA41F6C4914B3BCD0, 0x71EEA8CF5356CF28, 0xADB7E97512C1B9AD,
        0x8081936D54481DD8, 0x661D4798E2309692, 0x7EAE28B576532950,
        0x3D2B0B32A1E52137, 0x2406A4B8304E264A, 0x1329C47EBABBB9A8,
        0x9D7AFFEA975A94CF, 0xABFBCFEA7171F4AA, 0x3BA19A1A3D28B102
    };

    uint64_t res_h[NUM_SIZE_64];

    for (int i = 0; i < 3; ++i)
    {
        /// nonce = ind - 1;

        /// PrintPuzzleSolution(
        ///     (uint8_t *)&nonce, (uint8_t *)(res_h + ((ind - 1) << 3)),
        ///     logstr
        /// );

        // copy results to host
        uint64_t res_h[3 * NUM_SIZE_64];

        CUDA_CALL(cudaMemcpy(
            (void *)res_h, (void *)(res_d + indices[i] * NUM_SIZE_32),
            NUM_SIZE_8, cudaMemcpyDeviceToHost
        ));

        if (memcmp(res_h, res + i * NUM_SIZE_64, NUM_SIZE_8))
        {
            LOG(ERROR) << "Test failed";
            exit(EXIT_FAILURE);
        }
    }

    LOG(INFO) << "Test passed";

// pk = 0x02 0C16DFC5E23C5935 7E89D44977038F0A 7851CC9926B3AABB 3FF9E7E6A57315AD
// w = 0x03 D8C897324F166363 9479D96A038263C4 7D76A5847A1E9916 95D29568856B41AF

    return;
}

// test.cu
