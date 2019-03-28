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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <inttypes.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <curl/curl.h>
#include <cuda.h>

////////////////////////////////////////////////////////////////////////////////
//  Read secret key
////////////////////////////////////////////////////////////////////////////////
int ReadSecKey(
    char * filename,
    char * out
)
{
    FILE * in = fopen(filename, "r");

    for (int i = 0; i < NUM_SIZE_4; ++i)
    {
        if ((out[i] = fgetc(in)) == EOF)
        {
            return 1;
        }
    }

    out[NUM_SIZE_4] = '\0';

    fclose(in);

    return 0;
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
//  Termination handler
////////////////////////////////////////////////////////////////////////////////
int KeyboardHitHandler(
    void
)
{
    termios oldt;
    termios newt;
    int ch;
    int oldf;

    tcgetattr(STDIN_FILENO, &oldt);

    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);

    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);

    if (ch != EOF)
    {
        ungetc(ch, stdin);

        printf("Commencing termination\n");
        fflush(stdout);

        return 1;
    }

    return 0;
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
        REVERSE_ENDIAN(((uint64_t *)((uint8_t *)pk + 1)) + 0),
        REVERSE_ENDIAN(((uint64_t *)((uint8_t *)pk + 1)) + 1),
        REVERSE_ENDIAN(((uint64_t *)((uint8_t *)pk + 1)) + 2),
        REVERSE_ENDIAN(((uint64_t *)((uint8_t *)pk + 1)) + 3)
    );

    ///printf(
    ///    "sk    =    0x%016lX %016lX %016lX %016lX\n",
    ///    ((uint64_t *)sk)[3], ((uint64_t *)sk)[2],
    ///    ((uint64_t *)sk)[1], ((uint64_t *)sk)[0]
    ///);

    printf(
        "w     = 0x%02lX %016lX %016lX %016lX %016lX\n",
        ((uint8_t *)w)[0],
        REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w + 1)) + 0),
        REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w + 1)) + 1),
        REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w + 1)) + 2),
        REVERSE_ENDIAN(((uint64_t *)((uint8_t *)w + 1)) + 3)
    );

    ///printf(
    ///    "x     =    0x%016lX %016lX %016lX %016lX\n",
    ///    ((uint64_t *)x)[3], ((uint64_t *)x)[2],
    ///    ((uint64_t *)x)[1], ((uint64_t *)x)[0]
    ///);

    printf(
        "b     =    0x%016lX %016lX %016lX %016lX\n",
        ((uint64_t *)bound)[3], ((uint64_t *)bound)[2],
        ((uint64_t *)bound)[1], ((uint64_t *)bound)[0]
    );

    return 0;
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

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//  Main cycle
////////////////////////////////////////////////////////////////////////////////
int main(
    int argc, char ** argv
)
{
    int deviceCount;
    CUDA_CALL(cudaGetDeviceCount(&deviceCount));

    if (!deviceCount)
    {
        printf("ABORT: GPU devices did not recognised.");

        return 1;
    }

    CALL_STATUS(curl_global_init(CURL_GLOBAL_ALL), ERROR_CURL, CURLE_OK);

    //====================================================================//
    //  Host memory allocation
    //====================================================================//
    // curl http request variables
    string_t request;
    jsmntok_t tokens[T_LEN];
    InitString(&request);

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
    char filename[10] = "./seckey";
    char skstr[NUM_SIZE_4 + 1];
    char pkstr[PK_SIZE_4 + 1];

    //====================================================================//
    //  Secret key reading and checking
    //====================================================================//
    if (argc == 1)
    {
        printf("Using secret key from './seckey'\n");
        fflush(stdout);

        if (access(filename, F_OK) == -1)
        {
            printf("ABORT: File \"./seckey\" not found\n");

            return 1;
        }
    }
    else
    {
        if (access(argv[1], F_OK) == -1)
        {
            printf("ABORT: File not found\n");

            return 1;
        }
    }

    // read secret key hex string from file
    if (ReadSecKey((argc == 1)? filename: argv[1], skstr) == 1)
    {
        printf("ABORT: Incompatible secret key format\n");
    }

    // convert secret key to little endian
    HexStrToLittleEndian(skstr, NUM_SIZE_4, sk_h, NUM_SIZE_8);

    // generate public key from secret key
    GeneratePublicKey(skstr, pkstr, pk_h);

    //====================================================================//
    //  Device memory allocation
    //====================================================================//
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
    state_t state = STATE_KEYGEN;
    uint32_t ind = 0;
    uint64_t base = 0;

    do
    {
        // curl http GET request
        if (GetLatestBlock(pkstr, &request, tokens, bound_h, mes_h, &state))
        {
            printf("ABORT: Your secret key is not valid\n");

            return 1;
        }

        // state is changed
        if (state != STATE_CONTINUE)
        {
            // generate one-time key pair
            GenerateKeyPair(x_h, w_h);

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

            // precalculate hashes
            if (state == STATE_REHASH)
            {
                Prehash(data_d, hash_d, indices_d);
            }

            state = STATE_CONTINUE;

            ///printf("Prehash finished\n");
            ///fflush(stdout);

            PrintPuzzleState(mes_h, pk_h, sk_h, w_h, x_h, bound_h);
        }

        CUDA_CALL(cudaDeviceSynchronize());

        // generate nonces
        GenerateConseqNonces<<<1 + (H_LEN * L_LEN - 1) / B_DIM, B_DIM>>>(
            (uint64_t *)nonce_d, N_LEN, base
        );

        base += H_LEN * L_LEN;

        // calculate unfinalized hash of message
        InitMining(&ctx_h, (uint32_t *)mes_h, NUM_SIZE_8);

        // copy context
        CUDA_CALL(cudaMemcpy(
            (void *)(data_d + PK2_SIZE_32 + 3 * NUM_SIZE_32), (void *)&ctx_h,
            sizeof(blake2b_ctx), cudaMemcpyHostToDevice
        ));

        // calculate solution candidates
        BlockMining<<<1 + (L_LEN - 1) / B_DIM, B_DIM>>>(
            bound_d, data_d, nonce_d, hash_d, res_d, indices_d
        );

        // try to find solution
        ind = FindNonZero(indices_d, indices_d + H_LEN * L_LEN, H_LEN * L_LEN);

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
            PostPuzzleSolution(w_h, nonce_h, res_h);

            state = STATE_KEYGEN;
        }
    }
    while(!KeyboardHitHandler());

    CUDA_CALL(cudaDeviceSynchronize());

    //====================================================================//
    //  Free device memory
    //====================================================================//
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

    curl_global_cleanup();

    return 0;
}

// autolykos.cu
