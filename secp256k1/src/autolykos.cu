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
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
 
////////////////////////////////////////////////////////////////////////////////
//  Find file size
////////////////////////////////////////////////////////////////////////////////
long int FindFileSize(
    const char * filename
)
{
    struct stat st;

    CALL_STATUS(stat(filename, &st), ERROR_STAT, 0);

    return st.st_size;
}

////////////////////////////////////////////////////////////////////////////////
//  Read config file
////////////////////////////////////////////////////////////////////////////////
int ReadConfig(
    char * filename,
    string_t * out,
    jsmntok_t * tokens
)
{
    FILE * in = fopen(filename, "r");

    long int size = FindFileSize(filename); 

    FUNCTION_CALL(out->ptr, (char *)realloc(out->ptr, size + 1), ERROR_ALLOC);

    for (int i = 0; (out->ptr[i] = fgetc(in)) != EOF; ++i) {}

    fclose(in);

    out->ptr[size] = '\0'; 
    out->len = size;

    jsmn_parser parser;

    jsmn_init(&parser);
    jsmn_parse(&parser, out->ptr, out->len, tokens, C_LEN);

    if (tokens[SK_POS].end - tokens[SK_POS].start != NUM_SIZE_4)
    {
        free(out->ptr);

        return EXIT_FAILURE;
    }

    char ch;

    for (int i = 0; i < NUM_SIZE_4; ++i)
    {
        ch = out->ptr[i + tokens[SK_POS].start]
            = toupper(out->ptr[i + tokens[SK_POS].start]);

        if (!(ch >= '0' && ch <= '9') && !(ch >= 'A' && ch <= 'F'))
        {
            free(out->ptr);

            return EXIT_FAILURE;
        }
    }

    out->ptr[tokens[SK_POS].end] = '\0';
    out->ptr[tokens[FROM_POS].end] = '\0';
    out->ptr[tokens[TO_POS].end] = '\0';
    out->ptr[tokens[KEEP_POS].end] = '\0';

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Generate consequtive nonces
////////////////////////////////////////////////////////////////////////////////
__global__ void GenerateConseqNonces(
    uint64_t * arr,
    uint32_t len,
    uint64_t base
)
{
    uint32_t tid = threadIdx.x + blockDim.x * blockIdx.x;

    uint64_t nonce = base + tid;

    INPLACE_REVERSE_ENDIAN(&nonce);

    if (tid < len) arr[tid] = nonce;

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Print Autolukos puzzle state variables
////////////////////////////////////////////////////////////////////////////////
int PrintPuzzleState(
    const uint8_t * mes,
    const uint8_t * pk,
    const uint8_t * sk,
    const uint8_t * w,
    const uint8_t * x,
    const uint8_t * bound
)
{
    printf("Processing candidate:\n"); 

    printf(
        "m     =    0x%016lX %016lX %016lX %016lX\n",
        REVERSE_ENDIAN((uint64_t *)mes + 0),
        REVERSE_ENDIAN((uint64_t *)mes + 1),
        REVERSE_ENDIAN((uint64_t *)mes + 2),
        REVERSE_ENDIAN((uint64_t *)mes + 3)
    );

    printf(
        "pk    = 0x%02lX %016lX %016lX %016lX %016lX\n",
        ((uint8_t *)pk)[0],
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 0),
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 1),
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 2),
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 3)
    );

    printf(
        "w     = 0x%02lX %016lX %016lX %016lX %016lX\n",
        ((uint8_t *)w)[0],
        REVERSE_ENDIAN((uint64_t *)(w + 1) + 0),
        REVERSE_ENDIAN((uint64_t *)(w + 1) + 1),
        REVERSE_ENDIAN((uint64_t *)(w + 1) + 2),
        REVERSE_ENDIAN((uint64_t *)(w + 1) + 3)
    );

    printf(
        "b     =    0x%016lX %016lX %016lX %016lX\n",
        ((uint64_t *)bound)[3], ((uint64_t *)bound)[2],
        ((uint64_t *)bound)[1], ((uint64_t *)bound)[0]
    );

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Print Autolukos puzzle solution
////////////////////////////////////////////////////////////////////////////////
int PrintPuzzleSolution(
    const uint8_t * nonce,
    const uint8_t * sol
)
{
    printf("Solution found:\n"); 

    printf("nonce =    0x%016lX\n", REVERSE_ENDIAN((uint64_t *)nonce));

    printf(
        "d     =    0x%016lX %016lX %016lX %016lX\n",
        ((uint64_t *)sol)[3], ((uint64_t *)sol)[2],
        ((uint64_t *)sol)[1], ((uint64_t *)sol)[0]
    );

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Main cycle
////////////////////////////////////////////////////////////////////////////////
int main(
    int argc,
    char ** argv
)
{
    int status = EXIT_SUCCESS;

    //====================================================================//
    //  GPU availability checking
    //====================================================================//
    int deviceCount;
    CUDA_CALL(cudaGetDeviceCount(&deviceCount));

    if (!deviceCount)
    {
        fprintf(stderr, "ABORT: GPU devices are not recognised.");

        return EXIT_FAILURE;
    }

    CALL_STATUS(curl_global_init(CURL_GLOBAL_ALL), ERROR_CURL, CURLE_OK);

    //====================================================================//
    //  Host memory allocation
    //====================================================================//
    // curl http request variables
    string_t request;
    InitString(&request);

    jsmntok_t reqtoks[T_LEN];

    // hash context
    // (212 + 4) bytes
    blake2b_ctx ctx_h;

    // autolykos variables
    uint8_t bound_h[NUM_SIZE_8];
    uint8_t mes_h[NUM_SIZE_8];
    uint8_t sk_h[NUM_SIZE_8];
    uint8_t pk_h[PK_SIZE_8];
    uint8_t x_h[NUM_SIZE_8];
    uint8_t w_h[PK_SIZE_8];
    uint8_t res_h[NUM_SIZE_8];
    uint8_t nonce_h[NONCE_SIZE_8];

    // cryptography variables
    char * skstr;
    char pkstr[PK_SIZE_4 + 1];

    // config variables
    string_t config;
    InitString(&config);

    jsmntok_t conftoks[C_LEN];

    char confname[9] = "./config";
    char * filename = (argc == 1)? confname: argv[1];

    //====================================================================//
    //  Config reading and checking
    //====================================================================//
    printf(
        "========================================"
        "========================================"
        "\nUsing configuration from \'%s\'\n", filename
    );
    fflush(stdout);

    // check access to config file
    if (access(filename, F_OK) == -1)
    {
        fprintf(stderr, "ABORT: File \'%s\' not found\n", filename);

        if (request.ptr)
        {
            free(request.ptr);
        }

        return EXIT_FAILURE;
    }

    // read config from file
    if (ReadConfig(filename, &config, conftoks) == EXIT_FAILURE)
    {
        fprintf(stderr, "ABORT: Incompatible secret key format\n");

        if (request.ptr)
        {
            free(request.ptr);
        }

        if (config.ptr)
        {
            free(config.ptr);
        }

        return EXIT_FAILURE;
    }

    skstr = config.ptr + conftoks[SK_POS].start;
    printf("skstr = %s\n", skstr);

    // convert secret key to little endian
    HexStrToLittleEndian(skstr, NUM_SIZE_4, sk_h, NUM_SIZE_8);

    printf("Public key generation started\n");
    fflush(stdout);

    // generate public key from secret key
    GeneratePublicKey(skstr, pkstr, pk_h);

    printf("Public key generation finished\n");
    fflush(stdout);

    //====================================================================//
    //  Device memory allocation
    //====================================================================//
    printf("GPU memory allocation started\n");
    fflush(stdout);

    // boundary for puzzle
    // ~0 MB
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
    // (H_LEN * N_LEN * INDEX_SIZE_8 * 2 + 4) bytes // ~512 MB
    uint32_t * indices_d;
    CUDA_CALL(cudaMalloc(
        (void **)&indices_d, H_LEN * N_LEN * INDEX_SIZE_8 * 2 + 4
    ));

    // potential solutions of puzzle
    // H_LEN * L_LEN * NUM_SIZE_8 bytes // 128 MB
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc((void **)&res_d, H_LEN * L_LEN * NUM_SIZE_8));

    printf("GPU memory allocation finished\n");
    fflush(stdout);

    //====================================================================//
    printf("Key-pair transfer from host to GPU started\n");
    fflush(stdout);

    // copy public key
    CUDA_CALL(cudaMemcpy(
        (void *)data_d, (void *)pk_h, PK_SIZE_8, cudaMemcpyHostToDevice
    ));

    // copy secret key
    CUDA_CALL(cudaMemcpy(
        (void *)(data_d + PK2_SIZE_32 + 2 * NUM_SIZE_32), (void *)sk_h,
        NUM_SIZE_8, cudaMemcpyHostToDevice
    ));

    printf("Key-pair transfer from host to GPU finished\n");
    fflush(stdout);

    //====================================================================//
    //  Autolykos puzzle cycle
    //====================================================================//
    state_t state = STATE_KEYGEN;
    uint32_t ind = 0;
    uint64_t base = 0;

    do
    {
        printf("Getting latest candidate block\n");
        fflush(stdout);

        // curl http GET request
        if (
            (status = GetLatestBlock(
                &config, conftoks, pkstr, &request, reqtoks, bound_h, mes_h,
                &state
            )) == EXIT_FAILURE
        )
        {
            break;
        }

        printf("Latest candidate block is obtained\n");
        fflush(stdout);

        if (TerminationRequestHandler())
        {
            break;
        }

        // state is changed
        if (state != STATE_CONTINUE)
        {
            printf("One-time public key generation started\n");
            fflush(stdout);

            // generate one-time key pair
            GenerateKeyPair(x_h, w_h);

            printf("One-time public key generation finished\n");
            fflush(stdout);

            if (TerminationRequestHandler())
            {
                break;
            }

            PrintPuzzleState(mes_h, pk_h, sk_h, w_h, x_h, bound_h);

            printf("Data transfer from host to GPU started\n");
            fflush(stdout);

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

            printf("Data transfer from host to GPU finished\n");
            fflush(stdout);

            if (TerminationRequestHandler())
            {
                break;
            }

            // precalculate hashes
            if (state == STATE_REHASH)
            {
                printf("Prehash started\n");
                fflush(stdout);

                Prehash(data_d, hash_d, indices_d);

                printf("Prehash finished\n");
                fflush(stdout);
            }

            state = STATE_CONTINUE;
        }

        CUDA_CALL(cudaDeviceSynchronize());

        if (TerminationRequestHandler())
        {
            break;
        }

        printf("Next batch of nonces generation started\n");
        fflush(stdout);

        // generate nonces
        GenerateConseqNonces<<<1 + (H_LEN * L_LEN - 1) / B_DIM, B_DIM>>>(
            (uint64_t *)nonce_d, N_LEN, base
        );

        base += H_LEN * L_LEN;

        printf("Next batch of nonces generation finished\n");
        fflush(stdout);

        if (TerminationRequestHandler())
        {
            break;
        }

        printf("Mining context preparation on CPU started\n");
        fflush(stdout);

        // calculate unfinalized hash of message
        InitMining(&ctx_h, (uint32_t *)mes_h, NUM_SIZE_8);

        // copy context
        CUDA_CALL(cudaMemcpy(
            (void *)(data_d + PK2_SIZE_32 + 3 * NUM_SIZE_32), (void *)&ctx_h,
            sizeof(blake2b_ctx), cudaMemcpyHostToDevice
        ));

        printf("Mining context preparation on CPU finished\n");
        fflush(stdout);

        if (TerminationRequestHandler())
        {
            break;
        }

        printf("Mining iteration on GPU started\n");
        fflush(stdout);

        // calculate solution candidates
        BlockMining<<<1 + (L_LEN - 1) / B_DIM, B_DIM>>>(
            bound_d, data_d, nonce_d, hash_d, res_d, indices_d
        );

        printf("Mining iteration on GPU finished\n");
        fflush(stdout);

        if (TerminationRequestHandler())
        {
            break;
        }

        printf("Batch checking for solutions started\n");
        fflush(stdout);

        // try to find solution
        ind = FindNonZero(indices_d, indices_d + H_LEN * L_LEN, H_LEN * L_LEN);

        printf("Batch checking for solutions finished\n");
        fflush(stdout);

        if (ind)
        {
            CUDA_CALL(cudaMemcpy(
                (void *)res_h, (void *)(res_d + ((ind - 1) << 3)), NUM_SIZE_8,
                cudaMemcpyDeviceToHost
            ));

            CUDA_CALL(cudaMemcpy(
                (void *)nonce_h, (void *)(nonce_d + ((ind - 1) << 1)),
                NONCE_SIZE_8, cudaMemcpyDeviceToHost
            ));

            PrintPuzzleSolution(nonce_h, res_h);

            // curl http POST request
            PostPuzzleSolution(&config, conftoks, pkstr, w_h, nonce_h, res_h);

            printf(
                "Solution posted\n"
                "========================================"
                "========================================"
                "\n"
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
    printf("Deallocation resources started\n");
    fflush(stdout);

    CUDA_CALL(cudaFree(bound_d));
    CUDA_CALL(cudaFree(nonce_d));
    CUDA_CALL(cudaFree(hash_d));
    CUDA_CALL(cudaFree(data_d));
    CUDA_CALL(cudaFree(indices_d));
    CUDA_CALL(cudaFree(res_d));

    //====================================================================//
    //  Free host memory
    //====================================================================//
    if (request.ptr)
    {
        free(request.ptr);
    }

    if (config.ptr)
    {
        free(config.ptr);
    }

    curl_global_cleanup();

    printf("Deallocation resources finished\n");
    fflush(stdout);

    //====================================================================//
    printf("Miner is now terminated\n");
    fflush(stdout);

    return status;
}

// autolykos.cu
