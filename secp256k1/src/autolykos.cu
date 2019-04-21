// autolykos.cu

/*******************************************************************************

    AUTOLYKOS -- Autolykos puzzle cycle

*******************************************************************************/

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
#include <atomic>
#include <chrono>
#include <ctype.h>
#include <cuda.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <iostream>
#include <mutex>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

INITIALIZE_EASYLOGGINGPP

using namespace std::chrono;

void minerThread(int deviceId, info_t * info);

////////////////////////////////////////////////////////////////////////////////
//  Main
////////////////////////////////////////////////////////////////////////////////
int main(int argc, char ** argv)
{
    START_EASYLOGGINGPP(argc, argv);

    el::Loggers::reconfigureAllLoggers(
        el::ConfigurationType::Format, "%datetime %level [%thread] %msg"
    );
    el::Helpers::setThreadName("main thread");

    int deviceCount;
    //timestamp_t stamp;
    int status = EXIT_SUCCESS;

    info_t info;
    info.blockId = 1;

    if (cudaGetDeviceCount(&deviceCount) != cudaSuccess)
    {
        LOG(ERROR) << "Error checking GPU";
        return EXIT_FAILURE;
    }

    LOG(INFO) << "Using " << deviceCount << " GPU devices";

    PERSISTENT_CALL_STATUS(curl_global_init(CURL_GLOBAL_ALL), CURLE_OK);

    char confName[14] = "./config.json";
    char * fileName = (argc == 1)? confName: argv[1];
    char from[MAX_URL_SIZE];
    //char to[MAX_URL_SIZE];
    // int keepPrehash = 0;
    json_t request(0, REQ_LEN);
    
    LOG(INFO) << "Using configuration file " << fileName;

    // check access to config file
    if (access(fileName, F_OK) == -1)
    {
        LOG(ERROR) << "Config file " << fileName << " not found";
        return EXIT_FAILURE;
    }

    // read config from file
    status = ReadConfig(
        fileName, info.sk_h, info.skstr, from, info.to, &info.keepPrehash//,
        //&stamp
    );

    if (status == EXIT_FAILURE)
    {
        LOG(ERROR) << "Wrong config file format";
        return EXIT_FAILURE;
    }

    LOG(INFO) << "Block getting URL " << from;
    LOG(INFO) << "Solution posting URL " << info.to;

    // generate public key from secret key
    GeneratePublicKey(info.skstr, info.pkstr, info.pk_h);
    
    char logstr[1000];

    sprintf(logstr,
        "Generated public key:\n"
        "   pk = 0x%02lX %016lX %016lX %016lX %016lX",
        ((uint8_t *)info.pk_h)[0],
        REVERSE_ENDIAN((uint64_t *)(info.pk_h + 1) + 0),
        REVERSE_ENDIAN((uint64_t *)(info.pk_h + 1) + 1),
        REVERSE_ENDIAN((uint64_t *)(info.pk_h + 1) + 2),
        REVERSE_ENDIAN((uint64_t *)(info.pk_h + 1) + 3)
    );

    LOG(INFO) << logstr;

    status = GetLatestBlock(
        from, &request, &info, true
    );
    if(status != EXIT_SUCCESS)
    {
        LOG(INFO) << "First block getting request failed, maybe wrong node address?";
    }


    std::vector<std::thread> miners(deviceCount);

    for (int i = 0; i < deviceCount; ++i)
    {
        miners[i] = std::thread(minerThread, i, &info);
    }

    //====================================================================//
    //  Main cycle
    //====================================================================//
    // bomb node with HTTP with 10ms intervals, if new block came 
    // signal miners with blockId
    int curlcnt = 0;
    const int curltimes = 2000;

    // using namespace std::chrono;
    milliseconds ms = milliseconds::zero(); 

    while(!TerminationRequestHandler())
    {
        milliseconds start = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        );
        
        status = GetLatestBlock(
            from, &request, &info, false);
        
        if (status != EXIT_SUCCESS) { LOG(INFO) << "Getting block error"; }

        ms += duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        ) - start;

        ++curlcnt;

        if (!(curlcnt % curltimes))
        {
            LOG(INFO) << "Average curling time "
                << ms.count() / (double)curltimes << " ms";
            ms = milliseconds::zero();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(8));
    }    

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Miner thread cycle
////////////////////////////////////////////////////////////////////////////////
void minerThread(int deviceId, info_t * info)
{
    //int status = EXIT_SUCCESS;
    //timestamp_t stamp;
    state_t state = STATE_KEYGEN;
    char threadName[20];

    cudaSetDevice(deviceId);
    sprintf(threadName, "GPU %i miner", deviceId);
    el::Helpers::setThreadName(threadName);    

    //====================================================================//
    //  Host memory allocation
    //====================================================================//
    // curl http request
    json_t request(0, REQ_LEN);

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
    uint8_t nonce[NONCE_SIZE_8];

    // cryptography variables
    char skstr[NUM_SIZE_4];
    char pkstr[PK_SIZE_4 + 1];
    //char from[MAX_URL_SIZE];
    char to[MAX_URL_SIZE];
    int keepPrehash = 0;

    // thread info variables
    unsigned int blockId = 0;
    milliseconds start; 
    
    //====================================================================//
    //  Copy from global to thread local data
    //====================================================================//
    info->info_mutex.lock();

    memcpy(sk_h, info->sk_h, NUM_SIZE_8);
    memcpy(mes_h, info->mes_h, NUM_SIZE_8);
    memcpy(bound_h, info->bound_h, NUM_SIZE_8);
    memcpy(pk_h, info->pk_h, PK_SIZE_8);
    memcpy(pkstr, info->pkstr, (PK_SIZE_4 + 1) * sizeof(char));
    memcpy(skstr, info->skstr, NUM_SIZE_4 * sizeof(char));
    memcpy(to, info->to, MAX_URL_SIZE * sizeof(char));
    // blockId = info->blockId.load();
    keepPrehash = info->keepPrehash;
    
    info->info_mutex.unlock();
    
    //====================================================================//
    //  Device memory allocation
    //====================================================================//
    LOG(INFO) << "GPU " << deviceId << " allocating memory";

    // boundary for puzzle
    // ~0 MiB
    uint32_t * bound_d;
    CUDA_CALL(cudaMalloc((void **)&bound_d, NUM_SIZE_8));

    // data: pk || mes || w || padding || x || sk || ctx
    // (2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) bytes // ~0 MiB
    uint32_t * data_d;
    CUDA_CALL(cudaMalloc((void **)&data_d, (NUM_SIZE_8 + BLOCK_DIM) * 4));

    // precalculated hashes
    // N_LEN * NUM_SIZE_8 bytes // 2 GiB
    uint32_t * hashes_d;
    CUDA_CALL(cudaMalloc((void **)&hashes_d, (uint32_t)N_LEN * NUM_SIZE_8));

    // indices of unfinalized hashes
    // (THREAD_LEN * N_LEN * 2 + 1) * INDEX_SIZE_8 bytes // ~512 MiB
    uint32_t * indices_d;
    CUDA_CALL(cudaMalloc(
        (void **)&indices_d, (THREAD_LEN * N_LEN * 2 + 1) * INDEX_SIZE_8
    ));

    // potential solutions of puzzle
    // THREAD_LEN * LOAD_LEN * NUM_SIZE_8 bytes // 128 MiB
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc((void **)&res_d, THREAD_LEN * LOAD_LEN * NUM_SIZE_8));

    // unfinalized hash contexts
    // N_LEN * 80 bytes // 5 GiB
    ucontext_type * uctxs_d;

    if (keepPrehash)
    {
        CUDA_CALL(cudaMalloc(
            (void **)&uctxs_d, (uint32_t)N_LEN * sizeof(ucontext_type)
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
    //int diff = 0;
    uint32_t ind = 0;
    uint64_t base = 0;

    if (keepPrehash)
    {
        LOG(INFO) << "Preparing unfinalized hashes on GPU " << deviceId;

        UncompleteInitPrehash<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            data_d, uctxs_d
        );

        CUDA_CALL(cudaDeviceSynchronize());
    }

    int cntCycles = 0;
    int NCycles = 100;
    start = duration_cast<milliseconds>(system_clock::now().time_since_epoch());

    do
    {
        ++cntCycles;

        if (!(cntCycles % NCycles))
        {
            milliseconds timediff
                = duration_cast<milliseconds>(
                    system_clock::now().time_since_epoch()
                ) - start;

            LOG(INFO) << "GPU " << deviceId << " hashrate "
                << (double)LOAD_LEN * NCycles
                / ((double)1000 * timediff.count()) << " MH/s";

            start = duration_cast<milliseconds>(
                system_clock::now().time_since_epoch()
            );
        }
    
        // if solution was found by this thread, wait for new block to come 
        if (state == STATE_KEYGEN)
        {
            while(info->blockId.load() == blockId) {}

            state = STATE_CONTINUE;
        }

        uint_t controlId = info->blockId.load();

        if (blockId != controlId)
        {
            // if info->blockId changed
            // read new message and bound to thread-local mem
            info->info_mutex.lock();

            memcpy(mes_h, info->mes_h, NUM_SIZE_8);
            memcpy(bound_h, info->bound_h, NUM_SIZE_8);

            info->info_mutex.unlock();

            state = STATE_REHASH;
            LOG(INFO) << "GPU " << deviceId << " read new block data";
            blockId = controlId;
            
            GenerateKeyPair(x_h, w_h);
            // PrintPuzzleState(mes_h, pk_h, sk_h, w_h, x_h, bound_h, &stamp);
            VLOG(1) << "Generated new keypair,"
                << " copying new data in device memory now";

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

            VLOG(1) << "Starting prehashing with new block data";
            Prehash(keepPrehash, data_d, uctxs_d, hashes_d, indices_d);
 
            state = STATE_CONTINUE;
        }

        CUDA_CALL(cudaDeviceSynchronize());

        VLOG(1) << "Starting mining cycle";

        // restart iteration if new block was found
        if (blockId != info->blockId.load()) { continue; }

        // calculate unfinalized hash of message
        VLOG(1) << "Starting InitMining";
        InitMining(&ctx_h, (uint32_t *)mes_h, NUM_SIZE_8);

        // copy context
        CUDA_CALL(cudaMemcpy(
            (void *)(data_d + PK2_SIZE_32 + 3 * NUM_SIZE_32), (void *)&ctx_h,
            sizeof(context_t), cudaMemcpyHostToDevice
        ));

        // restart iteration if new block was found
        if (blockId != info->blockId.load()) { continue; }

        VLOG(1) << "Starting main BlockMining procedure";

        // calculate solution candidates
        BlockMining<<<1 + (LOAD_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            bound_d, data_d, base, hashes_d, res_d, indices_d
        );

        VLOG(1) << "Trying to find solution";

        // restart iteration if new block was found
        if (blockId != info->blockId.load()) { continue; }

        // try to find solution
        ind = FindNonZero(
            indices_d, indices_d + THREAD_LEN * LOAD_LEN, THREAD_LEN * LOAD_LEN
        );

        // solution found
        if (ind)
        {
            CUDA_CALL(cudaMemcpy(
                (void *)res_h, (void *)(res_d + ((ind - 1) << 3)), NUM_SIZE_8,
                cudaMemcpyDeviceToHost
            ));

            *((uint64_t *)nonce) = base + ind - 1;

            PrintPuzzleSolution(nonce, res_h);
            PostPuzzleSolution(to, pkstr, w_h, nonce, res_h);
            LOG(INFO) << "GPU " << deviceId << " found and posted a solution";
    
            state = STATE_KEYGEN;
        }

        base += THREAD_LEN * LOAD_LEN;
    }
    while(1); // !TerminationRequestHandler()); 

    return;
}

// autolykos.cu
