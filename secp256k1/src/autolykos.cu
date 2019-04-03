// autolykos.cu

/*******************************************************************************

    AUTOLYKOS -- Autolykos puzzle cycle

*******************************************************************************/

#include "../include/compaction.h"
#include "../include/conversion.h"
#include "../include/cryptography.h"
#include "../include/definitions.h"
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

////////////////////////////////////////////////////////////////////////////////
//  Main cycle
////////////////////////////////////////////////////////////////////////////////
int main(
    int argc,
    char ** argv
)
{
    int status = EXIT_SUCCESS;

    timestamp_t stamp;

    printf(
        "========================================"
        "========================================\n"
        "%s Checking GPU availability\n", TimeStamp(&stamp)
    );

    //====================================================================//
    //  GPU availability checking
    //====================================================================//
    int deviceCount;

    if (cudaGetDeviceCount(&deviceCount) != cudaSuccess)
    {
        fprintf(stderr, "ABORT:  GPU devices are not recognised.");

        fprintf(
            stderr, "%s Miner is now terminated\n"
            "========================================"
            "========================================\n",
            TimeStamp(&stamp)
        );
        return EXIT_FAILURE;
    }

    CALL_STATUS(curl_global_init(CURL_GLOBAL_ALL), ERROR_CURL, CURLE_OK);

    //====================================================================//
    //  Host memory allocation
    //====================================================================//
    // curl http request variables
    string_t request;
    jsmntok_t reqtoks[T_LEN];

    // hash context
    // (212 + 4) bytes
    context_t ctx_h;

    // autolykos variables
    uint8_t bound_h[NUM_SIZE_8];
    uint8_t mes_h[NUM_SIZE_8];
    uint8_t sk_h[NUM_SIZE_8];
    uint8_t pk_h[PK_SIZE_8];
    uint8_t x_h[NUM_SIZE_8];
    uint8_t w_h[PK_SIZE_8];
    uint8_t res_h[NUM_SIZE_8];
    uint8_t nonces_h[NONCE_SIZE_8];

    // cryptography variables
    char skstr[NUM_SIZE_4];
    char pkstr[PK_SIZE_4 + 1];

    // config variables
    char confname[14] = "./config.json";
    char * filename = (argc == 1)? confname: argv[1];
    char from[60];
    char to[60];
    int keepPrehash = 0;

    //====================================================================//
    //  Config reading and checking
    //====================================================================//
    printf(
        "Using configuration from \'%s\'\n", filename
    );
    fflush(stdout);

    // check access to config file
    if (access(filename, F_OK) == -1)
    {
        fprintf(stderr, "ABORT:  File \'%s\' not found\n", filename);

        fprintf(
            stderr, "%s Miner is now terminated\n"
            "========================================"
            "========================================\n",
            TimeStamp(&stamp)
        );

        return EXIT_FAILURE;
    }

    // read config from file
    status = ReadConfig(filename, sk_h, skstr, from, to, &keepPrehash, &stamp);

    /// to do /// proper config error check
    if (status == EXIT_FAILURE)
    {
        fprintf(stderr, "ABORT:  Wrong config format\n");

        fprintf(
            stderr, "%s Miner is now terminated\n"
            "========================================"
            "========================================\n",
            TimeStamp(&stamp)
        );

        return EXIT_FAILURE;
    }

    // generate public key from secret key
    GeneratePublicKey(skstr, pkstr, pk_h);

    printf(
        "%s Generated public key:\n"
        "   pk = 0x%02lX %016lX %016lX %016lX %016lX\n",
        TimeStamp(&stamp), ((uint8_t *)pk_h)[0],
        REVERSE_ENDIAN((uint64_t *)(pk_h + 1) + 0),
        REVERSE_ENDIAN((uint64_t *)(pk_h + 1) + 1),
        REVERSE_ENDIAN((uint64_t *)(pk_h + 1) + 2),
        REVERSE_ENDIAN((uint64_t *)(pk_h + 1) + 3)
    );
    fflush(stdout);

    //====================================================================//
    //  Device memory allocation
    //====================================================================//
    printf("%s Allocating GPU memory\n", TimeStamp(&stamp));
    fflush(stdout);

    // boundary for puzzle
    // ~0 MiB
    uint32_t * bound_d;
    CUDA_CALL(cudaMalloc((void **)&bound_d, NUM_SIZE_8));

    // nonces
    // H_LEN * L_LEN * NONCE_SIZE_8 bytes // 32 MiB
    uint32_t * nonces_d;
    CUDA_CALL(cudaMalloc((void **)&nonces_d, H_LEN * L_LEN * NONCE_SIZE_8));

    // data: pk || mes || w || padding || x || sk || ctx
    // (2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) bytes // ~0 MiB
    uint32_t * data_d;
    CUDA_CALL(cudaMalloc((void **)&data_d, (NUM_SIZE_8 + B_DIM) * 4));

    // precalculated hashes
    // N_LEN * NUM_SIZE_8 bytes // 2 GiB
    uint32_t * hashes_d;
    CUDA_CALL(cudaMalloc((void **)&hashes_d, (uint32_t)N_LEN * NUM_SIZE_8));

    // indices of unfinalized hashes
    // (H_LEN * N_LEN * 2 + 1) * INDEX_SIZE_8 bytes // ~512 MiB
    uint32_t * indices_d;
    CUDA_CALL(cudaMalloc(
        (void **)&indices_d, (H_LEN * N_LEN * 2 + 1) * INDEX_SIZE_8
    ));

    // potential solutions of puzzle
    // H_LEN * L_LEN * NUM_SIZE_8 bytes // 128 MiB
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc((void **)&res_d, H_LEN * L_LEN * NUM_SIZE_8));

    // unfinalized hash contexts
    // N_LEN * 80 bytes // 5 GiB
    ucontext_t * uctxs_d;

    if (keepPrehash)
    {
        CUDA_CALL(cudaMalloc(
            (void **)&uctxs_d, (uint32_t)N_LEN * sizeof(ucontext_t)
        ));
    }

    //====================================================================//
    //  Key-pair transfer form host to device
    //====================================================================//
    // copy public key
    CUDA_CALL(cudaMemcpy(
        (void *)data_d, (void *)pk_h, PK_SIZE_8, cudaMemcpyHostToDevice
    ));

    // copy secret key
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + PK2_SIZE_32 + 2 * NUM_SIZE_32), (void *)sk_h,
        NUM_SIZE_8, cudaMemcpyHostToDevice
    ));

    //====================================================================//
    //  Autolykos puzzle cycle
    //====================================================================//
    InitString(&request);

    state_t state = STATE_KEYGEN;
    int diff = 0;
    uint32_t ind = 0;
    uint64_t base = 0;

    if (keepPrehash)
    {
        printf(
            "%s Preparing unfinalized hashes\n"
            "========================================"
            "========================================\n",
            TimeStamp(&stamp)
        );
        fflush(stdout);


        UncompleteInitPrehash<<<1 + (N_LEN - 1) / B_DIM, B_DIM>>>(
            data_d, uctxs_d
        );

        CUDA_CALL(cudaDeviceSynchronize());
    }
    else
    {
        printf(
            "========================================"
            "========================================\n"
        );
        fflush(stdout);
    }

    do
    {
        if (TerminationRequestHandler())
        {
            break;
        }

        printf("%s Getting latest candidate block\n", TimeStamp(&stamp));
        fflush(stdout);

        // curl http GET request
        status = GetLatestBlock(
            from, pkstr, &request, reqtoks, bound_h, mes_h, &state, &diff
        );

        if (status == EXIT_FAILURE || state == STATE_INTERRUPT)
        {
            break;
        }

        if (TerminationRequestHandler())
        {
            break;
        }

        // state is changed
        if (state != STATE_CONTINUE)
        {
            // generate one-time key pair
            GenerateKeyPair(x_h, w_h);

            if (TerminationRequestHandler())
            {
                break;
            }

            PrintPuzzleState(mes_h, pk_h, sk_h, w_h, x_h, bound_h, &stamp);

            // copy boundary
            CUDA_CALL(cudaMemcpy(
                (void *)bound_d, (void *)bound_h, NUM_SIZE_8,
                cudaMemcpyHostToDevice
            ));

            // copy message
            CUDA_CALL(cudaMemcpy(
                (void *)((uint8_t *)data_d + PK_SIZE_8), (void *)mes_h,
                NUM_SIZE_8, cudaMemcpyHostToDevice
            ));

            // copy one time secret key
            CUDA_CALL(cudaMemcpy(
                (void *)(data_d + PK2_SIZE_32 + NUM_SIZE_32), (void *)x_h,
                NUM_SIZE_8, cudaMemcpyHostToDevice
            ));

            // copy one time public key
            CUDA_CALL(cudaMemcpy(
                (void *)((uint8_t *)data_d + PK_SIZE_8 + NUM_SIZE_8),
                (void *)w_h, PK_SIZE_8, cudaMemcpyHostToDevice
            ));

            if (TerminationRequestHandler())
            {
                break;
            }

            // precalculate hashes
            if (state == STATE_REHASH)
            {
                Prehash(keepPrehash, data_d, uctxs_d, hashes_d, indices_d);

                printf("%s Finalizing prehashes\n", TimeStamp(&stamp));
                fflush(stdout);
            }

            state = STATE_CONTINUE;
        }
        else
        {
            printf(
                "                              Obtained block is the same\n"
            );

            if (diff)
            {
                printf(
                    "       b = 0x%016lX %016lX %016lX %016lX\n",
                    ((uint64_t *)bound_h)[3], ((uint64_t *)bound_h)[2],
                    ((uint64_t *)bound_h)[1], ((uint64_t *)bound_h)[0]
                );

                diff = 0;
            }
            else
            {
                printf(
                    "                              "
                    "Obtained target is the same\n"
                );
            }

            fflush(stdout);
        }

        CUDA_CALL(cudaDeviceSynchronize());

        if (TerminationRequestHandler())
        {
            break;
        }

        printf(
            "%s Checking solutions for nonces:\n"
            "           0x%016lX -- 0x%016lX\n",
            TimeStamp(&stamp), base, base + H_LEN * L_LEN - 1
        );
        fflush(stdout);

        // generate nonces
        GenerateConseqNonces<<<1 + (H_LEN * L_LEN - 1) / B_DIM, B_DIM>>>(
            (uint64_t *)nonces_d, N_LEN, base
        );

        base += H_LEN * L_LEN;

        if (TerminationRequestHandler())
        {
            break;
        }

        // calculate unfinalized hash of message
        InitMining(&ctx_h, (uint32_t *)mes_h, NUM_SIZE_8);

        // copy context
        CUDA_CALL(cudaMemcpy(
            (void *)(data_d + PK2_SIZE_32 + 3 * NUM_SIZE_32), (void *)&ctx_h,
            sizeof(context_t), cudaMemcpyHostToDevice
        ));

        if (TerminationRequestHandler())
        {
            break;
        }

        // calculate solution candidates
        BlockMining<<<1 + (L_LEN - 1) / B_DIM, B_DIM>>>(
            bound_d, data_d, nonces_d, hashes_d, res_d, indices_d
        );

        if (TerminationRequestHandler())
        {
            break;
        }

        // try to find solution
        ind = FindNonZero(indices_d, indices_d + H_LEN * L_LEN, H_LEN * L_LEN);

        // solution found
        if (ind)
        {
            CUDA_CALL(cudaMemcpy(
                (void *)res_h, (void *)(res_d + ((ind - 1) << 3)), NUM_SIZE_8,
                cudaMemcpyDeviceToHost
            ));

            CUDA_CALL(cudaMemcpy(
                (void *)nonces_h, (void *)(nonces_d + ((ind - 1) << 1)),
                NONCE_SIZE_8, cudaMemcpyDeviceToHost
            ));

            printf("%s Solution found:\n", TimeStamp(&stamp)); 
            PrintPuzzleSolution(nonces_h, res_h);

            // curl http POST request
            PostPuzzleSolution(to, pkstr, w_h, nonces_h, res_h);

            printf(
                "%s Solution is posted\n"
                "========================================"
                "========================================\n",
                TimeStamp(&stamp)
            );
            fflush(stdout);

            state = STATE_KEYGEN;
        }
    }
    while(!TerminationRequestHandler());

    CUDA_CALL(cudaDeviceSynchronize());

    //====================================================================//
    //  Free device memory
    //====================================================================//
    printf("%s Releasing resources\n", TimeStamp(&stamp));
    fflush(stdout);

    CUDA_CALL(cudaFree(bound_d));
    CUDA_CALL(cudaFree(nonces_d));
    CUDA_CALL(cudaFree(hashes_d));
    CUDA_CALL(cudaFree(data_d));
    CUDA_CALL(cudaFree(indices_d));
    CUDA_CALL(cudaFree(res_d));

    if (keepPrehash)
    {
        CUDA_CALL(cudaFree(uctxs_d));
    }

    //====================================================================//
    //  Free host memory
    //====================================================================//
    FREE(request.ptr);

    curl_global_cleanup();

    //====================================================================//
    printf(
        "%s Miner is now terminated\n"
        "========================================"
        "========================================\n",
        TimeStamp(&stamp)
    );
    fflush(stdout);

    return status;
}

// autolykos.cu
