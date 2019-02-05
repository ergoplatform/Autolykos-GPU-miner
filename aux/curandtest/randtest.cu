#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cuda.h>
#include <curand.h>

#define CUDA_CALL(x) do { if((x) != cudaSuccess) {  \
printf("Error at %s:%d\n",__FILE__,__LINE__);       \
return EXIT_FAILURE;}} while(0)

#define CURAND_CALL(x) do { if((x) != CURAND_STATUS_SUCCESS) {  \
printf("Error at %s:%d\n",__FILE__,__LINE__);                   \
return EXIT_FAILURE;}} while(0)

int main(int argc, char * argv[])
{
    uint32_t i;
    uint32_t N = 1000000;

    curandGenerator_t gen;

    uint32_t * devData;
    uint32_t * hostData;

    hostData = (uint32_t *)calloc(N, sizeof(uint32_t));
    CUDA_CALL(cudaMalloc((void **)&devData, N * sizeof(uint32_t)));

    CURAND_CALL(curandCreateGenerator(&gen, CURAND_RNG_PSEUDO_MTGP32));
    
    time_t rawtime;
    time(&rawtime);
    CURAND_CALL(curandSetPseudoRandomGeneratorSeed(gen, (uint64_t)rawtime));

    CURAND_CALL(curandGenerate(gen, devData, N));

    CUDA_CALL(cudaMemcpy(
        hostData, devData, N * sizeof(uint32_t), cudaMemcpyDeviceToHost
    ));

    uint64_t total = 0;

    for (i = 0; i < N; i++)
    {
        if ((hostData[i]) & 0x80000000)
        {
            ++total;
        }
    }
    
    printf(
        "Fraction with nonzero highest bit was: %10.13g\n",
        (double)total / (double)N
    );

    CURAND_CALL(curandDestroyGenerator(gen));

    CUDA_CALL(cudaFree(devData));
    free(hostData);    

    return EXIT_SUCCESS;
}

