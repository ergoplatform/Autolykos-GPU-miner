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
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

////////////////////////////////////////////////////////////////////////////////
//  Time stamp
////////////////////////////////////////////////////////////////////////////////
char * TimeStamp(
    stamp_t * stamp
)
{
    // get real time
    clock_gettime(CLOCK_REALTIME, &(stamp->realtime));
    // convert seconds to human-readable form
    stamp->timeinfo = localtime(&((stamp->realtime).tv_sec));
    // form time stamp
    strftime(stamp->timestamp, 30, "%a %m/%d/%Y %H:%M:%S:", stamp->timeinfo);

    // calculate milliseconds
    long int millisec = (stamp->realtime).tv_nsec / 1e6;
    sprintf(stamp->timestamp + 24, "%03d: ", millisec);

    return stamp->timestamp;
}
 
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
        return EXIT_FAILURE;
    }

    char ch;

    for (int i = 0; i < NUM_SIZE_4; ++i)
    {
        ch = out->ptr[i + tokens[SK_POS].start]
            = toupper(out->ptr[i + tokens[SK_POS].start]);

        if (!(ch >= '0' && ch <= '9') && !(ch >= 'A' && ch <= 'F'))
        {
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

    fflush(stdout);

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
    printf("nonce =    0x%016lX\n", REVERSE_ENDIAN((uint64_t *)nonce));

    printf(
        "d     =    0x%016lX %016lX %016lX %016lX\n",
        ((uint64_t *)sol)[3], ((uint64_t *)sol)[2],
        ((uint64_t *)sol)[1], ((uint64_t *)sol)[0]
    );

    fflush(stdout);

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

    stamp_t stamp;

    printf(
        "========================================"
        "========================================\n"
        "%s Checking GPU availability\n", TimeStamp(&stamp)
    );
    fflush(stdout);

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
    blake2b_ctx ctx_h;

    // autolykos variables
    uint8_t bound_h[NUM_SIZE_8 * 2];
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
    jsmntok_t conftoks[C_LEN];

    char confname[9] = "./config";
    char * filename = (argc == 1)? confname: argv[1];

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

    InitString(&config);

    // read config from file
    if (ReadConfig(filename, &config, conftoks) == EXIT_FAILURE)
    {
        fprintf(stderr, "ABORT:  Wrong secret key format\n");

        if (config.ptr)
        {
            free(config.ptr);
        }

        fprintf(
            stderr, "%s Miner is now terminated\n"
            "========================================"
            "========================================\n",
            TimeStamp(&stamp)
        );
        return EXIT_FAILURE;
    }

    skstr = config.ptr + conftoks[SK_POS].start;

    // convert secret key to little endian
    HexStrToLittleEndian(skstr, NUM_SIZE_4, sk_h, NUM_SIZE_8);

    printf("%s Public key generation started\n", TimeStamp(&stamp));
    fflush(stdout);

    // generate public key from secret key
    GeneratePublicKey(skstr, pkstr, pk_h);

    printf("%s Public key generation finished\n", TimeStamp(&stamp));
    fflush(stdout);

    //====================================================================//
    //  Device memory allocation
    //====================================================================//
    printf("%s GPU memory allocation started\n", TimeStamp(&stamp));
    fflush(stdout);

    // boundary for puzzle
    // ~0 MB
    uint32_t * bound_d;
    CUDA_CALL(cudaMalloc((void **)&bound_d, NUM_SIZE_8 * 2));

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

    printf("%s GPU memory allocation finished\n", TimeStamp(&stamp));
    fflush(stdout);

    //====================================================================//
    printf(
        "%s Key-pair transfer from host to GPU started\n", TimeStamp(&stamp)
    );
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

    printf(
        "%s Key-pair transfer from host to GPU finished\n"
        "========================================"
        "========================================\n",
        TimeStamp(&stamp)
    );
    fflush(stdout);

    //====================================================================//
    //  Autolykos puzzle cycle
    //====================================================================//
    InitString(&request);

    state_t state = STATE_KEYGEN;
    uint32_t ind = 0;
    uint64_t base = 0;

    do
    {
        printf("%s Getting latest candidate block\n", TimeStamp(&stamp));
        fflush(stdout);

        // curl http GET request
        status = GetLatestBlock(
            &config, conftoks, pkstr, &request, reqtoks, bound_h, mes_h, &state
        );

        if (status == EXIT_FAILURE || state == STATE_INTERRUPT)
        {
            break;
        }

        printf("%s Latest candidate block is obtained\n", TimeStamp(&stamp));
        fflush(stdout);

        if (TerminationRequestHandler())
        {
            break;
        }

        // state is changed
        if (state != STATE_CONTINUE)
        {
            printf(
                "%s One-time public key generation started\n", TimeStamp(&stamp)
            );
            fflush(stdout);

            // generate one-time key pair
            GenerateKeyPair(x_h, w_h);

            printf(
                "%s One-time public key generation finished\n",
                TimeStamp(&stamp)
            );
            fflush(stdout);

            if (TerminationRequestHandler())
            {
                break;
            }

            printf("%s Processing candidate:\n", TimeStamp(&stamp)); 
            PrintPuzzleState(mes_h, pk_h, sk_h, w_h, x_h, bound_h);

            printf(
                "%s Data transfer from host to GPU started\n", TimeStamp(&stamp)
            );
            fflush(stdout);

            // copy boundary
            CUDA_CALL(cudaMemcpy(
                (void *)bound_d, (void *)bound_h, NUM_SIZE_8 * 2,
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

            printf(
                "%s Data transfer from host to GPU finished\n",
                TimeStamp(&stamp)
            );
            fflush(stdout);

            if (TerminationRequestHandler())
            {
                break;
            }

            // precalculate hashes
            if (state == STATE_REHASH)
            {
                printf("%s Prehash started\n", TimeStamp(&stamp));
                fflush(stdout);

                Prehash(data_d, hash_d, indices_d);

                printf("%s Prehash finished\n", TimeStamp(&stamp));
                fflush(stdout);
            }

            state = STATE_CONTINUE;
        }

        CUDA_CALL(cudaDeviceSynchronize());

        if (TerminationRequestHandler())
        {
            break;
        }

        printf(
            "%s Next batch of nonces generation started\n", TimeStamp(&stamp)
        );
        fflush(stdout);

        // generate nonces
        GenerateConseqNonces<<<1 + (H_LEN * L_LEN - 1) / B_DIM, B_DIM>>>(
            (uint64_t *)nonce_d, N_LEN, base
        );

        base += H_LEN * L_LEN;

        printf(
            "%s Next batch of nonces generation finished\n", TimeStamp(&stamp)
        );
        fflush(stdout);

        if (TerminationRequestHandler())
        {
            break;
        }

        printf(
            "%s Mining context preparation on CPU started\n", TimeStamp(&stamp)
        );
        fflush(stdout);

        // calculate unfinalized hash of message
        InitMining(&ctx_h, (uint32_t *)mes_h, NUM_SIZE_8);

        // copy context
        CUDA_CALL(cudaMemcpy(
            (void *)(data_d + PK2_SIZE_32 + 3 * NUM_SIZE_32), (void *)&ctx_h,
            sizeof(blake2b_ctx), cudaMemcpyHostToDevice
        ));

        printf(
            "%s Mining context preparation on CPU finished\n", TimeStamp(&stamp)
        );
        fflush(stdout);

        if (TerminationRequestHandler())
        {
            break;
        }

        printf("%s Mining iteration on GPU started\n", TimeStamp(&stamp));
        fflush(stdout);

        // calculate solution candidates
        BlockMining<<<1 + (L_LEN - 1) / B_DIM, B_DIM>>>(
            bound_d, data_d, nonce_d, hash_d, res_d, indices_d
        );

        printf("%s Mining iteration on GPU finished\n", TimeStamp(&stamp));
        fflush(stdout);

        if (TerminationRequestHandler())
        {
            break;
        }

        printf("%s Batch checking for solutions started\n", TimeStamp(&stamp));
        fflush(stdout);

        // try to find solution
        ind = FindNonZero(indices_d, indices_d + H_LEN * L_LEN, H_LEN * L_LEN);

        printf("%s Batch checking for solutions finished\n", TimeStamp(&stamp));
        fflush(stdout);

        // solution found
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

            printf("%s Solution found:\n", TimeStamp(&stamp)); 
            PrintPuzzleSolution(nonce_h, res_h);

            // curl http POST request
            PostPuzzleSolution(&config, conftoks, pkstr, w_h, nonce_h, res_h);

            printf(
                "%s Solution is posted\n"
                "========================================"
                "========================================\n",
                TimeStamp(&stamp)
            );
            fflush(stdout);

            state = STATE_KEYGEN;
        }
        // solution not found
        else
        {
            printf("Solution is not found in the current batch of nonces\n");
            fflush(stdout);
        }
    }
    while(!TerminationRequestHandler());

    CUDA_CALL(cudaDeviceSynchronize());

    //====================================================================//
    //  Free device memory
    //====================================================================//
    printf("%s Resources releasing started\n", TimeStamp(&stamp));
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

    printf("%s Resources releasing finished\n", TimeStamp(&stamp));
    fflush(stdout);

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
