// autolykos.cu

/*******************************************************************************

    AUTOLYKOS -- Autolykos puzzle cycle

*******************************************************************************/

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include "bip39/include/bip39/bip39.h"
#include "../include/cryptography.h"
#include "../include/definitions.h"
#include "../include/easylogging++.h"
#include "../include/jsmn.h"
#include "../include/mining.h"
#include "../include/prehash.h"
#include "../include/processing.h"
#include "../include/reduction.h"
#include "../include/request.h"
#include "../include/httpapi.h"
#include "../include/queue.h"
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
#include <random>

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

void SenderThread(info_t * info, BlockQueue<MinerShare>* shQueue)
{
    while(true)
    {
        MinerShare share = shQueue->get();
        char logstr[2048];
        
        uint64_t* r = (uint64_t*)share.d;
        uint64_t* bound = (uint64_t*)(info->bound); 

        int issol = ((uint64_t *)r)[3] < ((uint64_t *)bound)[3]
        || (((uint64_t *)r)[3] == ((uint64_t *)bound)[3] && (
            ((uint64_t *)r)[2] < ((uint64_t *)bound)[2]
            || ((uint64_t *)r)[2] == ((uint64_t *)bound)[2] && (
                ((uint64_t *)r)[1] < ((uint64_t *)bound)[1]
                || ((uint64_t *)r)[1] == ((uint64_t *)bound)[1]
                && ((uint64_t *)r)[0] < ((uint64_t *)bound)[0]
            )
        ));
        PrintPuzzleSolution((uint8_t*)&share.nonce, (uint8_t*)share.d, logstr);
        if(issol)
        {        
            LOG(INFO) << "Some GPU"
            << " found and trying to POST a solution:\n" << logstr;
            PostPuzzleSolution(info->to, info->pkstr, share.pubkey_w, (uint8_t*)&share.nonce, share.d);
        }
        else
        {
            LOG(INFO) << "Some GPU"
            << " found and trying to POST a share to the pool:\n" << logstr;
            PostPuzzleSolution(info->pool, info->pkstr, share.pubkey_w, (uint8_t*)&share.nonce, share.d);
        }
        

    }


}

////////////////////////////////////////////////////////////////////////////////
//  Miner thread cycle
////////////////////////////////////////////////////////////////////////////////
void MinerThread(int deviceId, info_t * info, std::vector<double>* hashrates, std::vector<int>* tstamps, BlockQueue<MinerShare>* shQueue)
{
    CUDA_CALL(cudaSetDevice(deviceId));
    cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
    char threadName[20];
    sprintf(threadName, "GPU %i miner", deviceId);
    el::Helpers::setThreadName(threadName);    

    state_t state = STATE_KEYGEN;
    char logstr[1000];

    //========================================================================//
    //  Host memory allocation
    //========================================================================//
    // CURL http request
    json_t request(0, REQ_LEN);

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
    uint8_t res_h[NUM_SIZE_8*MAX_SOLS];
    uint8_t nonce[NONCE_SIZE_8];

    char skstr[NUM_SIZE_4];
    char pkstr[PK_SIZE_4 + 1];
    char to[MAX_URL_SIZE];
    int keepPrehash = 0;

    // thread info variables
    uint_t blockId = 0;
    milliseconds start; 
    
    //========================================================================//
    //  Copy from global to thread local data
    //========================================================================//
    info->info_mutex.lock();

    
    memcpy(sk_h, info->sk, NUM_SIZE_8);
    memcpy(mes_h, info->mes, NUM_SIZE_8);
    memcpy(bound_h, info->poolbound, NUM_SIZE_8);
    memcpy(pk_h, info->pk, PK_SIZE_8);
    memcpy(pkstr, info->pkstr, (PK_SIZE_4 + 1) * sizeof(char));
    memcpy(skstr, info->skstr, NUM_SIZE_4 * sizeof(char));
    memcpy(to, info->to, MAX_URL_SIZE * sizeof(char));
    // blockId = info->blockId.load();
    keepPrehash = info->keepPrehash;
    
    info->info_mutex.unlock();
    
    //========================================================================//
    //  Check GPU memory
    //========================================================================//
    size_t freeMem;
    size_t totalMem;

    CUDA_CALL(cudaMemGetInfo(&freeMem, &totalMem));
    
    if (freeMem < MIN_FREE_MEMORY)
    {
        LOG(ERROR) << "Not enough GPU memory for mining,"
            << " minimum 2.8 GiB needed";

        return;
    }

    if (keepPrehash && freeMem < MIN_FREE_MEMORY_PREHASH)
    {
        LOG(ERROR) << "Not enough memory for keeping prehashes, "
                   << "setting keepPrehash to false";

        keepPrehash = 0;
    }

    //========================================================================//
    //  Device memory allocation
    //========================================================================//
    LOG(INFO) << "GPU " << deviceId << " allocating memory";

    // boundary for puzzle
    uint32_t * bound_d;
    // (2 * PK_SIZE_8 + 2 + 4 * NUM_SIZE_8 + 212 + 4) bytes // ~0 MiB
    CUDA_CALL(cudaMalloc(&bound_d, NUM_SIZE_8 + DATA_SIZE_8));
    // data: pk || mes || w || padding || x || sk || ctx
    uint32_t * data_d = bound_d + NUM_SIZE_32;
    
    uint32_t* BHashes;
    CUDA_CALL(cudaMalloc(&BHashes, NUM_SIZE_8*THREADS_PER_ITER));

    // precalculated hashes
    // N_LEN * NUM_SIZE_8 bytes // 2 GiB
    uint32_t * hashes_d;
    CUDA_CALL(cudaMalloc(&hashes_d, (uint32_t)N_LEN * NUM_SIZE_8));

    // place to handle result of the puzzle
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc(&res_d, NUM_SIZE_8*MAX_SOLS));
    uint32_t * indices_d;
    CUDA_CALL(cudaMalloc(&indices_d, MAX_SOLS*sizeof(uint32_t)));

    // place to handle nonce if solution is found
    uint32_t indices_h[MAX_SOLS];
    
    uint32_t * count_d;

    CUDA_CALL(cudaMalloc(&count_d,sizeof(uint32_t)));

    CUDA_CALL(cudaMemset(count_d,0,sizeof(uint32_t)));

    
    CUDA_CALL(cudaMemset(
        indices_d, 0, sizeof(uint32_t)*MAX_SOLS
    ));

    // unfinalized hash contexts
    // if keepPrehash == true // N_LEN * 80 bytes // 5 GiB
    uctx_t * uctxs_d = NULL;

    if (keepPrehash)
    {
        CUDA_CALL(cudaMalloc(&uctxs_d, (uint32_t)N_LEN * sizeof(uctx_t)));
    }

    //========================================================================//
    //  Key-pair transfer form host to device
    //========================================================================//
    // copy public key
    CUDA_CALL(cudaMemcpy(
        data_d, pk_h, PK_SIZE_8, cudaMemcpyHostToDevice
    ));

    // copy secret key
    CUDA_CALL(cudaMemcpy(
        data_d + COUPLED_PK_SIZE_32 + 2 * NUM_SIZE_32, sk_h, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    //========================================================================//
    //  Autolykos puzzle cycle
    //========================================================================//
    uint32_t ind = 0;
    uint64_t base = 0;

    // set unfinalized hash contexts if necessary
    if (keepPrehash)
    {
        LOG(INFO) << "Preparing unfinalized hashes on GPU " << deviceId;

        UncompleteInitPrehash<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            data_d, uctxs_d
        );

        CUDA_CALL(cudaDeviceSynchronize());
    }

    int cntCycles = 0;
    int NCycles = 50;

    // wait for the very first block to come before starting
    while (info->blockId.load() == 0) {}

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
            
            // change avg hashrate in global memory

            (*hashrates)[deviceId] = (double)NONCES_PER_ITER * (double)NCycles
                / ((double)1000 * timediff.count());
             
            start = duration_cast<milliseconds>(
                system_clock::now().time_since_epoch()
            );

            (*tstamps)[deviceId] = start.count();
        }
    
        // if solution was found by this thread wait for new block to come 
        if (state == STATE_KEYGEN)
        {
            while (info->blockId.load() == blockId) {}

            state = STATE_CONTINUE;
        }

        uint_t controlId = info->blockId.load();
        
        if (blockId != controlId)
        {
            // if info->blockId changed
            // read new message and bound to thread-local mem
            info->info_mutex.lock();

            memcpy(mes_h, info->mes, NUM_SIZE_8);
            memcpy(bound_h, info->poolbound, NUM_SIZE_8);

            info->info_mutex.unlock();

            LOG(INFO) << "GPU " << deviceId << " read new block data";
            blockId = controlId;
            
            GenerateKeyPair(x_h, w_h);

            VLOG(1) << "Generated new keypair,"
                << " copying new data in device memory now";

            // copy boundary
            CUDA_CALL(cudaMemcpy(
                bound_d, bound_h, NUM_SIZE_8, cudaMemcpyHostToDevice
            ));

            // copy message
            CUDA_CALL(cudaMemcpy(
                ((uint8_t *)data_d + PK_SIZE_8), mes_h, NUM_SIZE_8,
                cudaMemcpyHostToDevice
            ));

            // copy one time secret key
            CUDA_CALL(cudaMemcpy(
                (data_d + COUPLED_PK_SIZE_32 + NUM_SIZE_32),
                x_h, NUM_SIZE_8, cudaMemcpyHostToDevice
            ));

            // copy one time public key
            CUDA_CALL(cudaMemcpy(
                ((uint8_t *)data_d + PK_SIZE_8 + NUM_SIZE_8),
                w_h, PK_SIZE_8, cudaMemcpyHostToDevice
            ));

            VLOG(1) << "Starting prehashing with new block data";
            Prehash(keepPrehash, data_d, uctxs_d, hashes_d, res_d);
            
            // calculate unfinalized hash of message

            VLOG(1) << "Starting InitMining";
            InitMining(&ctx_h, (uint32_t *)mes_h, NUM_SIZE_8);

            CUDA_CALL(cudaDeviceSynchronize());
    
            // copy context
            CUDA_CALL(cudaMemcpy(
                data_d + COUPLED_PK_SIZE_32 + 3 * NUM_SIZE_32, &ctx_h,
                sizeof(ctx_t), cudaMemcpyHostToDevice
            ));

            state = STATE_CONTINUE;
        }

        VLOG(1) << "Starting main BlockMining procedure";
        BlakeHash<<<1 + (THREADS_PER_ITER - 1) / BLOCK_DIM, BLOCK_DIM>>>(data_d, base, BHashes);
        // calculate solution candidates
        BlockMining<<<1 + (THREADS_PER_ITER - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            bound_d, data_d, base, hashes_d, res_d, indices_d, count_d,BHashes
        );
        
        CUDA_CALL(cudaPeekAtLastError());

        VLOG(1) << "Trying to find solution";

        // restart iteration if new block was found
        if (blockId != info->blockId.load()) { continue; }

        CUDA_CALL(cudaMemcpy(
            indices_h, indices_d, sizeof(uint32_t)*MAX_SOLS,
            cudaMemcpyDeviceToHost
        ));

        int i = 0;
        // solution found
        if(indices_h[0])
        {
            CUDA_CALL(cudaMemcpy(
                res_h, res_d , NUM_SIZE_8*MAX_SOLS,
                cudaMemcpyDeviceToHost
            ));
            while(indices_h[i] && i < MAX_SOLS)
            {
 
                *((uint64_t *)nonce) = base + indices_h[i] - 1;
                
                MinerShare share(*((uint64_t *)nonce), w_h, res_h + NUM_SIZE_32*i);
                shQueue->put(share);
                /*

                PrintPuzzleSolution(nonce, res_h, logstr);
    

                PostPuzzleSolution(to, pkstr, w_h, nonce, res_h);
        
                state = STATE_KEYGEN;
                
                */
                i++;
   
            }
            LOG(INFO) << "Found " << i << " shares";
            CUDA_CALL(cudaMemset(
                indices_d, 0, sizeof(uint32_t)*MAX_SOLS
            ));
            CUDA_CALL(cudaMemset(count_d,0,sizeof(uint32_t)));

        }
        base += NONCES_PER_ITER;
    }
    while (1);

}

////////////////////////////////////////////////////////////////////////////////
//  Main
////////////////////////////////////////////////////////////////////////////////
int main(int argc, char ** argv)
{
    //========================================================================//
    //  Setup log
    //========================================================================//
    START_EASYLOGGINGPP(argc, argv);

    el::Loggers::reconfigureAllLoggers(
        el::ConfigurationType::Format, "%datetime %level [%thread] %msg"
    );

    el::Helpers::setThreadName("main thread");

    char logstr[1000];

    // Mnemonic generation mode
    if(argc > 1)
    {
        if(!strcmp(argv[1],"-G"))
        {
            if(checkRandomDevice() == EXIT_SUCCESS)
            {
                std::string mnemonic = BIP39::generate_mnemonic(BIP39::entropy_bits_t::_192).to_string();
                LOG(INFO) << "!!!Generated new mnemonic, put it in your config.json file!!!\n" <<
                    mnemonic << 
                "\n!!!Generated new mnemonic, put it in your config.json file!!!"; 
                char skstr[NUM_SIZE_4];
                char pkstr[PK_SIZE_4 + 1];
                uint8_t sk[NUM_SIZE_8];
                uint8_t pk[PK_SIZE_8];
                GenerateSecKeyNew(
                    mnemonic.c_str(), strlen(mnemonic.c_str()), sk,
                    skstr, ""
                );    
                char logstr_gen[1000];
                GeneratePublicKey(skstr, pkstr, pk);
                PrintPublicKey(pkstr, logstr_gen);
                LOG(INFO) << "Generated public key:\n   " << logstr_gen;
            
                exit(EXIT_SUCCESS);
            }
            else
            {
                LOG(ERROR) << "No good randomness source, can't generate mnemonic";
                exit(EXIT_SUCCESS);
            }
        }
    }



    //========================================================================//
    //  Check GPU availability
    //========================================================================//
    int deviceCount;
    int status = EXIT_SUCCESS;

    if (cudaGetDeviceCount(&deviceCount) != cudaSuccess)
    {
        LOG(ERROR) << "Error checking GPU";
        return EXIT_FAILURE;
    }

    LOG(INFO) << "Using " << deviceCount << " GPU devices";

    //========================================================================//
    //  Read configuration file
    //========================================================================//
    char confName[14] = "./config.json";
    char * fileName = (argc == 1)? confName: argv[1];
    char from[MAX_URL_SIZE];
    info_t info;
    info.blockId = 0;
    info.keepPrehash = 0;
    
    BlockQueue<MinerShare> solQueue;


    LOG(INFO) << "Using configuration file " << fileName;

    // check access to config file
    if (access(fileName, F_OK) == -1)
    {
        LOG(ERROR) << "Configuration file " << fileName << " is not found";
        return EXIT_FAILURE;
    }

    // read configuration from file
    status = ReadConfig(
        fileName, info.sk, info.skstr, from, info.to, info.pool, &info.keepPrehash
    );

    if (status == EXIT_FAILURE) { return EXIT_FAILURE; }

    LOG(INFO) << "Block getting URL:\n   " << from;
    LOG(INFO) << "Solution posting URL:\n   " << info.to;

    // generate public key from secret key
    GeneratePublicKey(info.skstr, info.pkstr, info.pk);

    PrintPublicKey(info.pkstr, logstr);
    LOG(INFO) << "Generated public key:\n   " << logstr;

    //========================================================================//
    //  Setup CURL
    //========================================================================//
    // CURL http request
    json_t request(0, REQ_LEN);

    // CURL init
    PERSISTENT_CALL_STATUS(curl_global_init(CURL_GLOBAL_ALL), CURLE_OK);
    

    //========================================================================//
    //  Fork miner threads
    //========================================================================//
    std::vector<std::thread> miners(deviceCount);
    std::vector<double> hashrates(deviceCount);
    std::vector<int> lastTimestamps(deviceCount);
    std::vector<int> timestamps(deviceCount);
    
    // PCI bus and device IDs
    std::vector<std::pair<int,int>> devinfos(deviceCount);
    for (int i = 0; i < deviceCount; ++i)
    {
        cudaDeviceProp props;
        if(cudaGetDeviceProperties(&props, i) == cudaSuccess)
        {
            devinfos[i] = std::make_pair(props.pciBusID, props.pciDeviceID);
        }
        miners[i] = std::thread(MinerThread, i, &info, &hashrates, &timestamps, &solQueue);
        hashrates[i] = 0;
        lastTimestamps[i] = 1;
        timestamps[i] = 0;
    }


    // get first block 
    status = EXIT_FAILURE;
    while(status != EXIT_SUCCESS)
    {
        status = GetLatestBlock(from, &request, &info, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        if(status != EXIT_SUCCESS)
        {
            LOG(INFO) << "Waiting for block data to be published by node...";
        }
    }
    std::thread solSender(SenderThread, &info, &solQueue);
    std::thread httpApi = std::thread(HttpApiThread,&hashrates,&devinfos);    

    //========================================================================//
    //  Main thread get-block cycle
    //========================================================================//
    uint_t curlcnt = 0;
    const uint_t curltimes = 2000;

    milliseconds ms = milliseconds::zero(); 
    


    // bomb node with HTTP with 10ms intervals, if new block came 
    // signal miners with blockId
    while (1)
    {
        milliseconds start = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        );
        
        // get latest block
        status = GetLatestBlock(from, &request, &info, 0);
        
        if (status != EXIT_SUCCESS) { LOG(INFO) << "Getting block error"; }

        ms += duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        ) - start;

        ++curlcnt;

        if (!(curlcnt % curltimes))
        {
            LOG(INFO) << "Average curling time "
                << ms.count() / (double)curltimes << " ms";
            LOG(INFO) << "Current block candidate: " << request.ptr;
            ms = milliseconds::zero();
            std::stringstream hrBuffer;
            hrBuffer << "Average hashrates: ";
            double totalHr = 0;
            for(int i = 0; i < deviceCount; ++i)
            {
                // check if miner thread is updating hashrate, e.g. alive
                if(!(curlcnt % (5*curltimes)))
                {
                    if(lastTimestamps[i] == timestamps[i])
                    {
                        hashrates[i] = 0;
                    }
                    lastTimestamps[i] = timestamps[i];
                }
                hrBuffer << "GPU" << i << " " << hashrates[i] << " MH/s ";
                totalHr += hashrates[i];
                
            }
            hrBuffer << "Total " << totalHr << " MH/s ";
            LOG(INFO) << hrBuffer.str();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }    

    return EXIT_SUCCESS;
}

// autolykos.cu
