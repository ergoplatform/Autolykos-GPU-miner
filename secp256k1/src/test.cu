// test.cu

/*******************************************************************************

    TEST -- hash functions test suite

*******************************************************************************/

#include "../include/cryptography.h"
#include "../include/definitions.h"
#include "../include/easylogging++.h"
#include "../include/mining.h"
#include "../include/prehash.h"
#include "../include/reduction.h"
#include "../include/request.h"
#include <ctype.h>
#include <cuda.h>
#include <cuda_runtime.h>
#include <cooperative_groups.h>
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

INITIALIZE_EASYLOGGINGPP

namespace ch = std::chrono;

////////////////////////////////////////////////////////////////////////////////
//  Test solutions correctness
////////////////////////////////////////////////////////////////////////////////
int TestSolutions(
    const info_t * info,
    const uint8_t * x,
    const uint8_t * w
)
{
    LOG(INFO) << "Solutions test started";
    LOG(INFO) << "Set keepPrehash = " << ((info->keepPrehash)? "true": "false");

    //========================================================================//
    //  Host memory allocation
    //========================================================================//
    // hash context
    // (212 + 4) bytes
    ctx_t ctx_h;

    //========================================================================//
    //  Device memory allocation
    //========================================================================//
    // boundary for puzzle
    // ~0 MiB
    uint32_t * bound_d;
    CUDA_CALL(cudaMalloc(&bound_d, NUM_SIZE_8 + DATA_SIZE_8));
    // data: pk || mes || w || padding || x || sk || ctx
    // (2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) bytes // ~0 MiB
    uint32_t * data_d = bound_d + NUM_SIZE_32;

    // precalculated hashes
    // N_LEN * NUM_SIZE_8 bytes // 2 GiB
    uint32_t * hashes_d;
    CUDA_CALL(cudaMalloc(&hashes_d, (uint32_t)N_LEN * NUM_SIZE_8));

    // WORKSPACE_SIZE_8 bytes
    // potential solutions of puzzle
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc(&res_d, WORKSPACE_SIZE_8));
    // indices of unfinalized hashes
    uint32_t * indices_d = res_d + NONCES_PER_ITER * NUM_SIZE_32;

    uctx_t * uctxs_d = NULL;

    if (info->keepPrehash)
    {
        CUDA_CALL(cudaMalloc(&uctxs_d, (uint32_t)N_LEN * sizeof(uctx_t)));
    }

    //========================================================================//
    //  Data transfer form host to device
    //========================================================================//
    // copy boundary
    CUDA_CALL(cudaMemcpy(
        bound_d, info->bound, NUM_SIZE_8, cudaMemcpyHostToDevice
    ));

    // copy public key
    CUDA_CALL(cudaMemcpy(data_d, info->pk, PK_SIZE_8, cudaMemcpyHostToDevice));

    // copy message
    CUDA_CALL(cudaMemcpy(
        (uint8_t *)data_d + PK_SIZE_8, info->mes, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    // copy one time public key
    CUDA_CALL(cudaMemcpy(
        (uint8_t *)data_d + PK_SIZE_8 + NUM_SIZE_8, w, PK_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    // copy one time secret key
    CUDA_CALL(cudaMemcpy(
        data_d + COUPLED_PK_SIZE_32 + NUM_SIZE_32, x, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    // copy secret key
    CUDA_CALL(cudaMemcpy(
        data_d + COUPLED_PK_SIZE_32 + 2 * NUM_SIZE_32, info->sk, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    //========================================================================//
    //  Test solutions
    //========================================================================//
    uint64_t base = 0;

    if (info->keepPrehash)
    {
        UncompleteInitPrehash<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            data_d, uctxs_d
        );
    }

    Prehash(info->keepPrehash, data_d, uctxs_d, hashes_d, res_d);
    CUDA_CALL(cudaDeviceSynchronize());

    // calculate unfinalized hash of message
    InitMining(&ctx_h, (uint32_t *)info->mes, NUM_SIZE_8);

    // copy context
    CUDA_CALL(cudaMemcpy(
        data_d + COUPLED_PK_SIZE_32 + 3 * NUM_SIZE_32, &ctx_h, sizeof(ctx_t),
        cudaMemcpyHostToDevice
    ));

    // calculate solution candidates
    BlockMining<<<1 + (THREADS_PER_ITER - 1) / BLOCK_DIM, BLOCK_DIM>>>(
        bound_d, data_d, base, hashes_d, res_d, indices_d
    );

    uint64_t res_h[NUM_SIZE_64];
    uint32_t solFound = 0;
    uint32_t nonce;
    // copy results to host
    CUDA_CALL(cudaMemcpy(
        res_h, res_d, NUM_SIZE_8,
        cudaMemcpyDeviceToHost
    ));
    CUDA_CALL(cudaMemcpy(
        &nonce, indices_d, sizeof(uint32_t),
        cudaMemcpyDeviceToHost
    ));
    LOG(INFO) << "Found nonce: " << nonce-1;
    if(nonce != 0x3381BF)
    {
        LOG(ERROR) << "Solutions test failed: wrong nonce";
        exit(EXIT_FAILURE);
    }

    //========================================================================//
    //  Device memory deallocation
    //========================================================================//
    CUDA_CALL(cudaFree(bound_d));
    CUDA_CALL(cudaFree(hashes_d));
    CUDA_CALL(cudaFree(res_d));

    if (info->keepPrehash) { CUDA_CALL(cudaFree(uctxs_d)); }

    LOG(INFO) << "Solutions test passed\n";

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Test performance
////////////////////////////////////////////////////////////////////////////////
int TestPerformance(
    const info_t * info,
    const uint8_t * x,
    const uint8_t * w
)
{
    LOG(INFO) << "Performance test started";

    //========================================================================//
    //  Host memory allocation
    //========================================================================//
    // hash context
    // (212 + 4) bytes
    ctx_t ctx_h;

    //========================================================================//
    //  Device memory allocation
    //========================================================================//
    // boundary for puzzle
    // ~0 MiB
    uint32_t * bound_d;
    CUDA_CALL(cudaMalloc(&bound_d, NUM_SIZE_8 + DATA_SIZE_8));
    // data: pk || mes || w || padding || x || sk || ctx
    // (2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + 212 + 4) bytes // ~0 MiB
    uint32_t * data_d = bound_d + NUM_SIZE_32;

    // precalculated hashes
    // N_LEN * NUM_SIZE_8 bytes // 2 GiB
    uint32_t * hashes_d;
    CUDA_CALL(cudaMalloc(&hashes_d, (uint32_t)N_LEN * NUM_SIZE_8));

    // WORKSPACE_SIZE_8 bytes
    // potential solutions of puzzle
    uint32_t * res_d;
    CUDA_CALL(cudaMalloc(&res_d, WORKSPACE_SIZE_8));
    // indices of unfinalized hashes
    uint32_t * indices_d = res_d + NONCES_PER_ITER * NUM_SIZE_32;

    uctx_t * uctxs_d = NULL;

    if (info->keepPrehash)
    {
        CUDA_CALL(cudaMalloc(&uctxs_d, (uint32_t)N_LEN * sizeof(uctx_t)));
    }

    //========================================================================//
    //  Data transfer form host to device
    //========================================================================//
    // copy boundary
    CUDA_CALL(cudaMemcpy(
        bound_d, info->bound, NUM_SIZE_8, cudaMemcpyHostToDevice
    ));

    // copy public key
    CUDA_CALL(cudaMemcpy(data_d, info->pk, PK_SIZE_8, cudaMemcpyHostToDevice));

    // copy message
    CUDA_CALL(cudaMemcpy(
        (uint8_t *)data_d + PK_SIZE_8, info->mes, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    // copy one time public key
    CUDA_CALL(cudaMemcpy(
        (uint8_t *)data_d + PK_SIZE_8 + NUM_SIZE_8, w, PK_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    // copy one time secret key
    CUDA_CALL(cudaMemcpy(
        data_d + COUPLED_PK_SIZE_32 + NUM_SIZE_32, x, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    // copy secret key
    CUDA_CALL(cudaMemcpy(
        data_d + COUPLED_PK_SIZE_32 + 2 * NUM_SIZE_32, info->sk, NUM_SIZE_8,
        cudaMemcpyHostToDevice
    ));

    //========================================================================//
    //  Test solutions
    //========================================================================//
    uint64_t base = 0;

    ch::milliseconds ms = ch::milliseconds::zero(); 

    LOG(INFO) << "Set keepPrehash = false";

    ch::milliseconds start = ch::duration_cast<ch::milliseconds>(
        ch::system_clock::now().time_since_epoch()
    );

    Prehash(0, data_d, NULL, hashes_d, res_d);

    CUDA_CALL(cudaDeviceSynchronize());
    
    ms = ch::duration_cast<ch::milliseconds>(
        ch::system_clock::now().time_since_epoch()
    ) - start;

    LOG(INFO) << "Prehash time: " << ms.count() << " ms";

    if (info->keepPrehash)
    {
        LOG(INFO) << "Set keepPrehash = true";

        UncompleteInitPrehash<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            data_d, uctxs_d
        );

        CUDA_CALL(cudaDeviceSynchronize());

        start = ch::duration_cast<ch::milliseconds>(
            ch::system_clock::now().time_since_epoch()
        );

        Prehash(1, data_d, uctxs_d, hashes_d, res_d);

        CUDA_CALL(cudaDeviceSynchronize());

        ms = ch::duration_cast<ch::milliseconds>(
            ch::system_clock::now().time_since_epoch()
        ) - start;

        LOG(INFO) << "Prehash time: " << ms.count() << " ms";
    }

    CUDA_CALL(cudaDeviceSynchronize());

    // calculate unfinalized hash of message
    InitMining(&ctx_h, (uint32_t *)info->mes, NUM_SIZE_8);

    // copy context
    CUDA_CALL(cudaMemcpy(
        data_d + COUPLED_PK_SIZE_32 + 3 * NUM_SIZE_32, &ctx_h, sizeof(ctx_t),
        cudaMemcpyHostToDevice
    ));

    LOG(INFO) << "BlockMining now for 1 minute";
    ms = ch::milliseconds::zero();

    uint32_t sum = 0;
    int iter = 0;
    uint32_t nonce = 0;
    start = ch::duration_cast<ch::milliseconds>(
        ch::system_clock::now().time_since_epoch()
    );

    for ( ; ms.count() < 60000; ++iter)
    {
        // calculate solution candidates
        BlockMining<<<1 + (THREADS_PER_ITER - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            bound_d, data_d, base, hashes_d, res_d, indices_d
        );

        CUDA_CALL(cudaMemcpy(
            &nonce, indices_d, sizeof(uint32_t),
            cudaMemcpyDeviceToHost
        ));

        if(nonce != 0) ++sum;

        CUDA_CALL(cudaMemset(indices_d, 0 ,sizeof(uint32_t)));
        // reduction now removed so no findsum
        //sum += FindSum(indices_d, indices_d + NONCES_PER_ITER, NONCES_PER_ITER);
        cudaDeviceSynchronize();
        base += NONCES_PER_ITER;

        ms = ch::duration_cast<ch::milliseconds>(
            ch::system_clock::now().time_since_epoch()
        ) - start;
    }

    //========================================================================//
    //  Device memory deallocation
    //========================================================================//
    CUDA_CALL(cudaFree(bound_d));
    CUDA_CALL(cudaFree(hashes_d));
    CUDA_CALL(cudaFree(res_d));

    if (info->keepPrehash) { CUDA_CALL(cudaFree(uctxs_d)); }

    LOG(INFO) << "Found " << sum << " solutions";
    LOG(INFO) << "Hashrate: " << (double)NONCES_PER_ITER * iter
        / ((double)1000 * ms.count()) << " MH/s";
    LOG(INFO) << "Performance test completed\n";

    return EXIT_SUCCESS;
}


// ugly stuff, will rewrite later
void TestRequests()
{
    json_t oldreq(0, REQ_LEN);
    json_t *newreq;
    newreq = new json_t(0, REQ_LEN);
    json_t oldreqbig(0, REQ_LEN);
    info_t testinfo;

    char bigrequest[] = "{ \"msg\" : \"46b7e94915275125129581725817295812759128"
                        "571925871285728572857285725285728571928517287519285718"
                        "275192857192857192857192587129581729587129581728571295"
                        "817295182759128751928571925871285782758782751928571827"
                        "519285787bfad202ab4e3dd9cc0603c1f61f53485854028b8fa03f"
                        "399544fb298\", \"b\" : 2134827235332678044033321050158"
                        "7889707005372997724693988999057291299,  \"pk\" : \"039"
                        "5f8d54fdd5edb7eeab3228c952d39f5e60d048178f94ac992d4f76"
                        "a6dce4c71\"  }";
    WriteFunc((void*)bigrequest, sizeof(char), strlen(bigrequest), &oldreqbig);
    if(strcmp(bigrequest, oldreqbig.ptr))
    {
        LOG(ERROR) << "WriteFunc strings do not match " 
        << bigrequest << "\n" << oldreqbig.ptr;
    }
    
    
    char request[] = "{ \"msg\" : \"46b7e949bfad202ab4e3dd9cc0603c1f61f5348585"
                     "4028b8fa03f399544fb298\", \"b\" : 2134827235332678044033"
                     "3210501587889707005372997724693988999057291299,  \"pk\" "
                     ": \"0395f8d54fdd5edb7eeab3228c952d39f5e60d048178f94ac992"
                     "d4f76a6dce4c71\"  }";

    WriteFunc((void*)request, sizeof(char), strlen(request), &oldreq);
    if(strcmp(request, oldreq.ptr))
    {
        LOG(ERROR) << "WriteFunc strings do not match " << request << "\n" << oldreq.ptr;
    }
    


    char seedstring[] = "13cc81ef0b13fd496217c7c44b16c09d923ad475d897cffd37c63"
                        "a15aebf579313d67934727d94ba42687f238480eb9248da9ba21e9c1";

    GenerateSecKey(
        seedstring, strlen(seedstring), testinfo.sk,
        testinfo.skstr
    );
    GeneratePublicKey(testinfo.skstr, testinfo.pkstr, testinfo.pk);

    char shortrequest[] =  "{ \"msg\" : \"46b7e\", \"b\" : 2134,  \"pk\" : \"0395"
                            "f8d54fdd5edb7eeab3228c952d39f5e60d048178f94ac992d4"
                            "f76a6dce4c71\"  }";
    char brokenrequest[] =  " \"msg\"  \"46b7e\", \"b\" : 2134,  \"pk\" : \"0395f8"
                            "d54fdd5edb7eeab3228c952d39f5e60d048178f94ac992d4f76a6"
                            "dce4c71\"  }";
    char uncompleterequest[] =  "{ \"msg\" : \"46b7e\", \"pk\" : \"0395f8d54fdd5edb"
                                "7eeab3228c952d39f5e60d048178f94ac992d4f76a6dce4c71\""
                                " }";
    char uncompleterequest2[] =  "{ \"b\" : 2134,  \"pk\" : \"0395f8d54fdd5edb7eeab"
                                 "3228c952d39f5e60d048178f94ac992d4f76a6dce4c71\"  }";

    WriteFunc((void*)shortrequest, sizeof(char), strlen(shortrequest), newreq);
    LOG(INFO) << "Testing short request "
     << "\n result " << ((ParseRequest(&oldreq, newreq, &testinfo, 1) == EXIT_SUCCESS) ? "OK" : "ERROR");
    delete newreq;
    newreq = new json_t(0, REQ_LEN);
    WriteFunc((void*)bigrequest, sizeof(char), strlen(bigrequest), newreq);
     LOG(INFO) << "Testing big request " 
      << "\n result " << ((ParseRequest(&oldreq, newreq, &testinfo, 1) == EXIT_SUCCESS) ? "OK" : "ERROR");
    delete newreq;
    newreq = new json_t(0, REQ_LEN);
    WriteFunc((void*)brokenrequest, sizeof(char), strlen(brokenrequest), newreq);
      LOG(INFO) << "Testing broken request " 
       << "\n result " << ((ParseRequest(&oldreq, newreq, &testinfo, 1) == EXIT_SUCCESS) ? "ERROR" : "OK");
    delete newreq;
    newreq = new json_t(0, REQ_LEN);
    WriteFunc((void*)uncompleterequest, sizeof(char), strlen(uncompleterequest), newreq);
       LOG(INFO) << "Testing uncomplete request 1 " 
        << "\n result " << ((ParseRequest(&oldreq, newreq, &testinfo, 1) == EXIT_SUCCESS) ? "ERROR" : "OK");
    delete newreq;
    newreq = new json_t(0, REQ_LEN);
    WriteFunc((void*)uncompleterequest2, sizeof(char), strlen(uncompleterequest2), newreq);
    LOG(INFO) << "Testing uncomplete request 2 " 
     << "\n result " << ((ParseRequest(&oldreq, newreq, &testinfo, 1) == EXIT_SUCCESS) ? "ERROR" : "OK");
    delete newreq;




}



void TestNewCrypto()
{
    char mnemonic[] = "edge talent poet tortoise trumpet dose";
    uint8_t sk[NUM_SIZE_8];
    char skstr[NUM_SIZE_4];
    char pkstr[PK_SIZE_4+1];
    uint8_t pk[PK_SIZE_8];

    GenerateSecKeyNew(mnemonic, strlen(mnemonic), sk, skstr, "");
    
    if(strncmp(skstr, "392F75AD23278B3CD7B060D900138F20F8CBA89ABB259B5DCF5D9830B49D8E38", NUM_SIZE_4))
    {
        printf("%.64s private key1\n", skstr);
        LOG(ERROR) << "mnemonic -> private key conversion does not work correctly";
    }
    else
    {
        LOG(INFO) << "Mnemonic -> private key conversion works OK";
    }

}



////////////////////////////////////////////////////////////////////////////////
//  Main
////////////////////////////////////////////////////////////////////////////////
int main(int argc, char ** argv)
{
    START_EASYLOGGINGPP(argc, argv);

    el::Loggers::reconfigureAllLoggers(
        el::ConfigurationType::Format, "%datetime %level [%thread] %msg"
    );

    el::Helpers::setThreadName("test thread");

    LOG(INFO) << "Checking crypto: ";

    TestNewCrypto();

    LOG(INFO) << "Testing requests:";

    TestRequests();
    //========================================================================//
    //  Check requirements
    //========================================================================//
    int deviceCount;

    if (cudaGetDeviceCount(&deviceCount) != cudaSuccess)
    {
        LOG(ERROR) << "Error checking GPU";
        exit(EXIT_FAILURE);
    }

    size_t freeMem;
    size_t totalMem;

    CUDA_CALL(cudaMemGetInfo(&freeMem, &totalMem));
    
    if (freeMem < MIN_FREE_MEMORY)
    {
        LOG(ERROR) << "Not enough GPU memory for mining,"
            << " minimum 2.8 GiB needed";

        exit(EXIT_FAILURE);
    }
    
    //========================================================================//
    //  Set test info
    //========================================================================//
    info_t info;
    uint8_t x[NUM_SIZE_8];
    uint8_t w[PK_SIZE_8];
    char seed[256] = "Va'esse deireadh aep eigean, va'esse eigh faidh'ar";

    // generate secret key from seed
    GenerateSecKey(seed, 50, info.sk, info.skstr);
    // generate public key from secret key
    GeneratePublicKey(info.skstr, info.pkstr, info.pk);

    const char ref_pkstr[PK_SIZE_4 + 1]
        = "020C16DFC5E23C59357E89D44977038F0A7851CC9926B3AABB3FF9E7E6A57315AD";

    int test = !strncmp(ref_pkstr, info.pkstr, PK_SIZE_4);

    if (!test)
    {
        LOG(ERROR) << "OpenSSL: generated wrong public key";
        return EXIT_FAILURE;
    }

    ((uint64_t *)info.bound)[0] = 0xFFFFFFFFFFFFFFFF;
    ((uint64_t *)info.bound)[1] = 0xFFFFFFFFFFFFFFFF;
    ((uint64_t *)info.bound)[2] = 0xFFFFFFFFFFFFFFFF;
    ((uint64_t *)info.bound)[3] = 0x000002FFFFFFFFFF;

    ((uint64_t *)info.mes)[0] = 1;
    ((uint64_t *)info.mes)[1] = 0;
    ((uint64_t *)info.mes)[2] = 0;
    ((uint64_t *)info.mes)[3] = 0;

    sprintf(seed, "%d", 0);

    // generate secret key from seed
    GenerateSecKey(seed, 1, x, info.skstr);
    // generate public key from secret key
    GeneratePublicKey(info.skstr, info.pkstr, w);

    //========================================================================//
    //  Run solutions correctness tests
    //========================================================================//
    if (NONCES_PER_ITER <= 0x3D5B84)
    {
        LOG(INFO) << "Need WORKSPACE value for at least 4021125,"
            << " skip solutions tests\n";
    }
    else
    {
        info.keepPrehash = 0;
        TestSolutions(&info, x, w);

        if (freeMem < MIN_FREE_MEMORY_PREHASH)
        {
            LOG(INFO) << "Not enough GPU memory for keeping prehashes, "
                << "skip test\n";
        }
        else
        {
            info.keepPrehash = 1;
            TestSolutions(&info, x, w);
        }
    }

    //========================================================================//
    //  Run performance tests
    //========================================================================//
    info.keepPrehash = (freeMem >= MIN_FREE_MEMORY_PREHASH)? 1: 0;
    TestPerformance(&info, x, w);

    LOG(INFO) << "Test suite executable is now terminated";

    return EXIT_SUCCESS;
}

// test.cu
