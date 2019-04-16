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
#include <atomic>
#include <thread>
#include <chrono>
#include <mutex>
#include <vector>
#include <iostream>
#define TEXT_SEPARATOR   "========================================"\
                         "========================================\n"
#define TEXT_GPUCHECK    " Checking GPU availability\n"
#define TEXT_TERMINATION " Miner is now terminated\n"
#define ERROR_GPUCHECK   "ABORT:  GPU devices are not recognised\n"

using namespace std::chrono;


struct globalInfo
{
    // Puzzle data to read
    
    uint8_t bound_h[NUM_SIZE_8];
    uint8_t mes_h[NUM_SIZE_8];
    uint8_t sk_h[NUM_SIZE_8];
    uint8_t pk_h[PK_SIZE_8];
    char skstr[NUM_SIZE_4];
    char pkstr[PK_SIZE_4 + 1];
    int keepPrehash;
    char to[40];
    // Mutex for reading/writing data from globalInfo safely

    std::mutex info_mutex;
    
    // Mutex for curl usage/maybe future websocket
    //not used now

    std::mutex io_mutex;

    // Increment when new block is sent by node

    std::atomic<unsigned int> blockId; 
};

void minerThread(int deviceId, globalInfo *info);


int main(int argc, char* argv[])
{
    int deviceCount;
    timestamp_t stamp;
    int status = EXIT_SUCCESS;
    globalInfo info;
    info.blockId = 1;
    state_t state = STATE_CONTINUE;
    if (cudaGetDeviceCount(&deviceCount) != cudaSuccess)
    {
        fprintf(
            stderr, ERROR_GPUCHECK "%s" TEXT_TERMINATION TEXT_SEPARATOR,
            TimeStamp(&stamp)
        );

        return EXIT_FAILURE;
    }

    printf("Using %i CUDA devices\n",deviceCount);

    PERSISTENT_CALL_STATUS(curl_global_init(CURL_GLOBAL_ALL), CURLE_OK);
	

    char confname[14] = "./config.json";
    char * filename = (argc == 1)? confname: argv[1];
    char from[40];
    char to[40];
    int diff;
   // int keepPrehash = 0;
    json_t request(0, REQ_LEN);
    
    printf(
        "Using configuration from \'%s\'\n", filename
    );
    fflush(stdout);

    // check access to config file
    if (access(filename, F_OK) == -1)
    {
        fprintf(stderr, "ABORT:  File \'%s\' not found\n", filename);

        fprintf(
            stderr, "%s" TEXT_TERMINATION TEXT_SEPARATOR, TimeStamp(&stamp)
        );

        return EXIT_FAILURE;
    }

    // read config from file
    status = ReadConfig(filename, info.sk_h, info.skstr, from, info.to, &info.keepPrehash, &stamp);

    if (status == EXIT_FAILURE)
    {
        fprintf(stderr, "ABORT:  Wrong config format\n");

        fprintf(
            stderr, "%s" TEXT_TERMINATION TEXT_SEPARATOR, TimeStamp(&stamp)
        );

        return EXIT_FAILURE;
    }

    // generate public key from secret key
    GeneratePublicKey(info.skstr, info.pkstr, info.pk_h);

    printf(
        "%s Generated public key:\n"
        "   pk = 0x%02lX %016lX %016lX %016lX %016lX\n",
        TimeStamp(&stamp), ((uint8_t *)info.pk_h)[0],
        REVERSE_ENDIAN((uint64_t *)(info.pk_h + 1) + 0),
        REVERSE_ENDIAN((uint64_t *)(info.pk_h + 1) + 1),
        REVERSE_ENDIAN((uint64_t *)(info.pk_h + 1) + 2),
        REVERSE_ENDIAN((uint64_t *)(info.pk_h + 1) + 3)
    );
    fflush(stdout);
    

    status = GetLatestBlock(
        from, info.pkstr, &request, info.bound_h, info.mes_h, &state, &diff
    );
    
    std::vector<std::thread> miners(deviceCount);
    for(int i = 0; i < deviceCount; i++)
    {
        miners[i] = std::thread(minerThread, i, &info);

    }

    // main cycle - bomb node with HTTP with 10ms intervals, if new block came 
    //-> signal miners with blockId
    int curlcnt = 0;
    const int curltimes = 2000;
    //time_t differ = 0;

    //using namespace std::chrono;
    milliseconds ms = milliseconds::zero(); 

    while(!TerminationRequestHandler())
    {
        milliseconds start = duration_cast< milliseconds >(
            system_clock::now().time_since_epoch()
            );
        info.info_mutex.lock();
        // need to fix state somehow
        state = STATE_CONTINUE;
        
        status = GetLatestBlock(
            from, info.pkstr, &request, info.bound_h, info.mes_h, &state, &diff
        );
        
        if(status != EXIT_SUCCESS)
	    {
	        printf("Getting block error\n");
	    }
        info.info_mutex.unlock();

        ms +=  duration_cast< milliseconds >(system_clock::now().time_since_epoch()) - start;
        curlcnt++;
        if(curlcnt%curltimes == 0)
        {
            //printf("Average curling time %lf\n",(double)differ/(CLOCKS_PER_SEC*curltimes));
            std::cout << "Average curling time " << ms.count()/(double)curltimes << " ms \n";
            ms = milliseconds::zero();
        }

        if(diff || state == STATE_REHASH)
        {
            info.blockId++;
            diff = 0;
            printf("Got new block in main thread\n");
	        fflush(stdout);
	    }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    }    


    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Main cycle
////////////////////////////////////////////////////////////////////////////////
void minerThread(int deviceId, globalInfo *info)
{
    int status = EXIT_SUCCESS;
    timestamp_t stamp;
    state_t state = STATE_KEYGEN;
    cudaSetDevice(deviceId);
    
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
    uint8_t nonces_h[NONCE_SIZE_8];

    // cryptography variables
    char skstr[NUM_SIZE_4];
    char pkstr[PK_SIZE_4 + 1];
    char from[40];
    char to[40];
    int keepPrehash = 0;
    unsigned int blockId = 0;
    milliseconds start;	
    
    // Copy from global to thread local data
    //===============================================

    info->info_mutex.lock();

    memcpy(sk_h,info->sk_h, NUM_SIZE_8*sizeof(uint8_t));
    memcpy(mes_h, info->mes_h, NUM_SIZE_8*sizeof(uint8_t));
    memcpy(bound_h, info->bound_h, NUM_SIZE_8*sizeof(uint8_t));
    memcpy(pk_h, info->pk_h, PK_SIZE_8*sizeof(uint8_t));
    memcpy(pkstr, info->pkstr, (PK_SIZE_4+1)*sizeof(uint8_t));
    memcpy(skstr, info->skstr, NUM_SIZE_4*sizeof(uint8_t));
    memcpy(to, info->to, 40*sizeof(char));
   // blockId = info->blockId.load();
    keepPrehash = info->keepPrehash;
    
    info->info_mutex.unlock();
    
    //end copy
    //===============================


    //====================================================================//
    //  Device memory allocation
    //====================================================================//
    printf(" %s thread GPU %i allocating GPU memory\n", TimeStamp(&stamp), deviceId);
   // fflush(stdout);

    // boundary for puzzle
    // ~0 MiB
    uint32_t * bound_d;
    CUDA_CALL(cudaMalloc((void **)&bound_d, NUM_SIZE_8));

    // nonces
    // THREAD_LEN * LOAD_LEN * NONCE_SIZE_8 bytes // 32 MiB
    uint32_t * nonces_d;
    CUDA_CALL(cudaMalloc(
        (void **)&nonces_d, THREAD_LEN * LOAD_LEN * NONCE_SIZE_8
    ));

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
    //state_t state = STATE_KEYGEN;
    int diff = 0;
    uint32_t ind = 0;
    uint64_t base = 0;

    if (keepPrehash)
    {
        printf(
            "%s Preparing unfinalized hashes\n" TEXT_SEPARATOR,
            TimeStamp(&stamp)
        );
        fflush(stdout);


        UncompleteInitPrehash<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            data_d, uctxs_d
        );

        CUDA_CALL(cudaDeviceSynchronize());
    }

    int cntCycles = 0;
    int NCycles = 100;
    start = duration_cast<milliseconds> (system_clock::now().time_since_epoch());
    do
    {
        
	    cntCycles++;
	    if(cntCycles%NCycles == 0)
	    {
            milliseconds timediff = duration_cast<milliseconds> (system_clock::now().time_since_epoch()) - start;
            printf("%lf MHashes per second on GPU %i \n", (double)LOAD_LEN*NCycles/((double)1000*timediff.count()), deviceId);
	        start = duration_cast<milliseconds> (system_clock::now().time_since_epoch());
	    }
	
        // if solution was found by this thread, wait for new block to come 
	    if(state == STATE_KEYGEN)
	    {
		    while(info->blockId.load() == blockId)
		    {}
		    state = STATE_CONTINUE;
	    }

	    unsigned int controlId = info->blockId.load();
        if(blockId != controlId)
        {
            //if info->blockId changed, read new message and bound to thread-local mem

            info->info_mutex.lock();
            memcpy(mes_h, info->mes_h, NUM_SIZE_8*sizeof(uint8_t));
            memcpy(bound_h, info->bound_h, NUM_SIZE_8*sizeof(uint8_t));
            /*
            for(int i = 0; i < NUM_SIZE_8; i++)
            {
                mes_h[i] = info->mes_h[i];
                bound_h[i] = info->bound_h[i];
            }
            */
            info->info_mutex.unlock();
            state = STATE_REHASH;
	        printf("Thread read new block data, blockid %i old %i\n",blockId,controlId);
	        blockId = controlId;
            
            GenerateKeyPair(x_h, w_h);
        
            //PrintPuzzleState(mes_h, pk_h, sk_h, w_h, x_h, bound_h, &stamp);

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
 
            Prehash(keepPrehash, data_d, uctxs_d, hashes_d, indices_d);
 

            state = STATE_CONTINUE;
    	    //printf("Prehashed for new block\n");
        }


        CUDA_CALL(cudaDeviceSynchronize());
 
         /*     printf(
            "%s Checking solutions for nonces:\n"
            "           0x%016lX -- 0x%016lX\n",
            TimeStamp(&stamp), base, base + THREAD_LEN * LOAD_LEN - 1
        );
        fflush(stdout);
        */   
        // generate nonces
        GenerateConseqNonces<<<1 + (THREAD_LEN * LOAD_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            (uint64_t *)nonces_d, N_LEN, base
        );

        base += THREAD_LEN * LOAD_LEN;
        // calculate unfinalized hash of message
        InitMining(&ctx_h, (uint32_t *)mes_h, NUM_SIZE_8);

        // copy context
        CUDA_CALL(cudaMemcpy(
            (void *)(data_d + PK2_SIZE_32 + 3 * NUM_SIZE_32), (void *)&ctx_h,
            sizeof(context_t), cudaMemcpyHostToDevice
        ));

        // calculate solution candidates
        BlockMining<<<1 + (LOAD_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            bound_d, data_d, nonces_d, hashes_d, res_d, indices_d
        );

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

            CUDA_CALL(cudaMemcpy(
                (void *)nonces_h, (void *)(nonces_d + ((ind - 1) << 1)),
                NONCE_SIZE_8, cudaMemcpyDeviceToHost
            ));

            printf("%s Solution found from GPU %i:\n", TimeStamp(&stamp), deviceId); 
            PrintPuzzleSolution(nonces_h, res_h);
            PostPuzzleSolution(to, pkstr, w_h, nonces_h, res_h);
            printf("new Solution is posted\n");
            fflush(stdout);
	
            state = STATE_KEYGEN;
        }
    }
    while(1); // !TerminationRequestHandler()); 

    return;
}

// autolykos.cu
