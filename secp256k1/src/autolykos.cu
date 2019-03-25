// autolykos.cu

/*******************************************************************************

    AUTOLYKOS -- Autolykos puzzle cycle

*******************************************************************************/

#include "../include/compaction.h"
#include "../include/conversion.h"
#include "../include/mining.h"
#include "../include/prehash.h"
#include "../include/request.h"
#include "../include/reduction.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <inttypes.h>
#include <unistd.h>
#include <curl/curl.h>
#include <cuda.h>
#include <curand.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

////////////////////////////////////////////////////////////////////////////////
//  Read secret key
////////////////////////////////////////////////////////////////////////////////
int ReadSecKey(
    char * filename,
    void * sk
)
{
    FILE * in = fopen(filename, "r");

    int status;

    for (int i = 0; i < NUM_SIZE_64; ++i)
    {
        status = fscanf(
            in, "%"SCNx64"\n", (uint64_t *)sk + NUM_SIZE_64 - i - 1
        );
    }

    fclose(in);

    return status;
}

////////////////////////////////////////////////////////////////////////////////
//  Generate key pair
////////////////////////////////////////////////////////////////////////////////
int GenerateKeyPair(
    uint8_t * sk,
    uint8_t * pk
)
{
    BIO * outbio = NULL;
    EC_KEY * eck = NULL;
    EVP_PKEY * evpk = NULL;
    int eccgrp;

    // initialize openssl
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // create Input/Output BIO's
    outbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    // create EC key sructure
    // set group type from NID
    eccgrp = OBJ_txt2nid("secp256k1");
    eck = EC_KEY_new_by_curve_name(eccgrp);

    // OPENSSL_EC_NAMED_CURVE flag for cert signing
    EC_KEY_set_asn1_flag(eck, OPENSSL_EC_NAMED_CURVE);

    // create public/private EC key pair
    if (!(EC_KEY_generate_key(eck)))
    {
        BIO_printf(outbio, "Error generating the ECC key.");
    }

    // convert EC key into PKEY structure
    evpk = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(evpk, eck))
    {
        BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");
    }

    // Now we show how to extract EC-specifics from the key
    eck = EVP_PKEY_get1_EC_KEY(evpk);

    const EC_GROUP * ecgrp = EC_KEY_get0_group(eck);

    //====================================================================//
    //  Public key extraction
    //====================================================================//
    const EC_POINT * ecp = EC_KEY_get0_public_key(eck);

    char * str = EC_POINT_point2hex(
        ecgrp, ecp, POINT_CONVERSION_COMPRESSED, NULL
    );

    int len = 0;

    if (str)
    {
        for ( ; str[len] != '\0'; ++len) {}
    }
    else
    {
        printf("ERROR\n");
        fflush(stdout);
    }

    HexStrToBigEndian(str, len, pk, PK_SIZE_8);

    OPENSSL_free(str);
    str = NULL;

    //====================================================================//
    //  Secret key extraction
    //====================================================================//
    const BIGNUM * bn = EC_KEY_get0_private_key(eck);

    str = BN_bn2hex(bn);
    len = 0;

    if (str)
    {
        for ( ; str[len] != '\0'; ++len) {}
    }
    else
    {
        printf("ERROR\n");
        fflush(stdout);
    }

    HexStrToLittleEndian(str, len, sk, NUM_SIZE_8);

    OPENSSL_free(str);

    //====================================================================//
    //  Deallocation
    //====================================================================//
    EVP_PKEY_free(evpk);
    EC_KEY_free(eck);
    BIO_free_all(outbio);

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
//  Main cycle
////////////////////////////////////////////////////////////////////////////////
int main(
    int argc, char ** argv
)
{
    int deviceCount;
    cudaGetDeviceCount(&deviceCount);

    if (!deviceCount)
    {
        printf("ABORT: GPU devices did not recognised.");

        return 1;
    }

    curl_global_init(CURL_GLOBAL_ALL);

    //====================================================================//
    //  Host memory allocation
    //====================================================================//
    uint8_t state = 1;
    uint32_t ind = 0;
    uint64_t base = 0;

    string block;
    InitString(&block);

    // hash context
    // (212 + 4) bytes
    blake2b_ctx ctx_h;

    uint8_t bound_h[NUM_SIZE_8];
    uint8_t mes_h[NUM_SIZE_8];
    uint8_t sk_h[NUM_SIZE_8];
    uint8_t pk_h[PK_SIZE_8];
    uint8_t x_h[NUM_SIZE_8];
    uint8_t w_h[PK_SIZE_8];
    uint8_t res_h[NUM_SIZE_8];
    uint8_t nonce_h[NONCE_SIZE_8];

    char filename[10] = "./seckey";

    if (argc == 1)
    {
        printf("Use secret key from './seckey'\n");
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

    ReadSecKey((argc == 1)? filename: argv[1], sk_h);

    //====================================================================//
    //  Device memory allocation
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
    //  Autolykos puzzle cycle
    //====================================================================//
    while (1)
    {
        GetLatestBlock(&block, bound_h, mes_h, pk_h, &state);

        // state is changed
        if (state)
        {
            // copy boundary
            CUDA_CALL(cudaMemcpy(
                (void *)bound_d, (void *)bound_h, NUM_SIZE_8,
                cudaMemcpyHostToDevice
            ));

            // copy public key
            CUDA_CALL(cudaMemcpy(
                (void *)data_d, (void *)pk_h, PK_SIZE_8, cudaMemcpyHostToDevice
            ));

            // copy message
            CUDA_CALL(cudaMemcpy(
                (void *)((uint8_t *)data_d + PK_SIZE_8), (void *)mes_h,
                NUM_SIZE_8, cudaMemcpyHostToDevice
            ));

            // copy secret key
            CUDA_CALL(cudaMemcpy(
                (void *)(data_d + PK2_SIZE_32 + 2 * NUM_SIZE_32), (void *)sk_h,
                NUM_SIZE_8, cudaMemcpyHostToDevice
            ));

            // generate one-time key pair
            GenerateKeyPair(x_h, w_h);

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
            Prehash(data_d, hash_d, indices_d);

            state = 0;

            printf("Prehash finished\n");
            fflush(stdout);

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
                "sk     = 0x%016lX %016lX %016lX %016lX\n",
                ((uint64_t *)sk_h)[3], ((uint64_t *)sk_h)[2],
                ((uint64_t *)sk_h)[1], ((uint64_t *)sk_h)[0]
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
                "x     = 0x%016lX %016lX %016lX %016lX\n",
                ((uint64_t *)x_h)[3], ((uint64_t *)x_h)[2],
                ((uint64_t *)x_h)[1], ((uint64_t *)x_h)[0]
            );

            printf(
                "b     = 0x%016lX %016lX %016lX %016lX\n",
                ((uint64_t *)bound_h)[3],
                ((uint64_t *)bound_h)[2],
                ((uint64_t *)bound_h)[1],
                ((uint64_t *)bound_h)[0]
            );
        }

        CUDA_CALL(cudaDeviceSynchronize());

        // generate nonces
        /// original /// CURAND_CALL(curandGenerate(gen, nonce_d, H_LEN * L_LEN * NONCE_SIZE_8));
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

            // printf("TRY");
            // fflush(stdout);

            printf(
                "nonce = 0x%016lX\n",
                ((uint64_t *)nonce_h)[0]
            );

            printf(
                "d     = 0x%016lX %016lX %016lX %016lX\n",
                ((uint64_t *)res_h)[3],
                ((uint64_t *)res_h)[2],
                ((uint64_t *)res_h)[1],
                ((uint64_t *)res_h)[0]
            );

            PostPuzzleSolution(w_h, nonce_h, res_h);

            state = 1;
        }

        struct timeval tmo;
        fd_set readfds;

        //printf(".");
        //fflush(stdout);

        FD_ZERO(&readfds);
        FD_SET(0, &readfds);
        tmo.tv_sec = 0.0001;
        tmo.tv_usec = 0;

        switch (select(1, &readfds, NULL, NULL, &tmo))
        {
            case -1:
                printf("Commencing termination\n");
                fflush(stdout);
                break;
            case 0:
                continue;
        }

        if (getchar() == 'e') {
            printf("Commencing termination\n");
            fflush(stdout);
            break;
        }
    }

    cudaDeviceSynchronize();

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

    //====================================================================//
    //  Free host memory
    //====================================================================//

    if (block.ptr)
    {
        free(block.ptr);
    }

    curl_global_cleanup();

    return 0;
}

// autolykos.cu
