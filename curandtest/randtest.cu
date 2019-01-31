#include <stdio.h>
#include <stdlib.h>
#include <cuda.h>
#include <curand.h>
// #include <curand_kernel.h>

/* include MTGP host helper functions */
#include <curand_mtgp32_host.h>
/* include MTGP pre-computed parameter sets */
#include <curand_mtgp32dc_p_11213.h>

#define CUDA_CALL(x) do { if((x) != cudaSuccess) {  \
printf("Error at %s:%d\n",__FILE__,__LINE__);       \
return EXIT_FAILURE;}} while(0)

#define CURAND_CALL(x) do { if((x) != CURAND_STATUS_SUCCESS) {  \
printf("Error at %s:%d\n",__FILE__,__LINE__);                   \
return EXIT_FAILURE;}} while(0)

/// __global__ void generate_kernel(
///     curandStateMtgp32 * state, 
///     int n,
///     int *result
/// ) {
///     int id = threadIdx.x + blockIdx.x * blockDim.x;
///     int count = 0;
///     unsigned int x;
///     /* Generate pseudo-random unsigned ints */
///     for(int i = 0; i < n; i++) {
///         x = curand(&state[blockIdx.x]);
///         /* Check if low bit set */
///         if(x & 1) {
///             count++;
///         }
///     }
///     /* Store results */
///     result[id] += count;
/// }

/// int main(int argc, char *argv[])
/// {
///     int blockSize;   // The launch configurator returned block size 
///     int minGridSize; // The minimum grid size needed to achieve the 
///     // maximum occupancy for a full device launch 
/// 
///     cudaOccupancyMaxPotentialBlockSize(
///         &minGridSize, &blockSize, generate_kernel, 0, 0
///     ); 
/// 
///     cudaDeviceSynchronize(); 
/// 
///     printf("grs = %d, bls = %d\n", minGridSize, blockSize);
///     ///
///     /// // calculate theoretical occupancy
///     /// int maxActiveBlocks;
///     /// cudaOccupancyMaxActiveBlocksPerMultiprocessor(
///     ///     &maxActiveBlocks, MyKernel, blockSize, 0
///     /// );
/// 
///     /// int device;
///     /// cudaDeviceProp props;
///     /// cudaGetDevice(&device);
///     /// cudaGetDeviceProperties(&props, device);
/// 
///     /// uint32_t occupancy = (maxActiveBlocks * blockSize / props.warpSize) / 
///     ///     (uint32_t)(props.maxThreadsPerMultiProcessor / props.warpSize);
/// 
///     /// printf(
///     ///     "Launched blocks of size %d. Theoretical occupancy: %f\n",
///     ///     blockSize, occupancy
///     /// );
/// 
///     int i;
///     uint64_t total;
///     curandStateMtgp32 * devMTGPStates;
///     mtgp32_kernel_params * devKernelParams;
/// 
///     int * devResults, * hostResults;
///     int sampleCount = 10000;
///     
///     /* Allow over-ride of sample count */    
///     if (argc == 2) {
///         sscanf(argv[1],"%d",&sampleCount);
///     }
///         
///     /* Allocate space for results on host */
///     hostResults = (int *)calloc(64 * 512, sizeof(int));
/// 
///     /* Allocate space for results on device */
///     CUDA_CALL(cudaMalloc((void **)&devResults, 64 * 512 * sizeof(int)));
/// 
///     /* Set results to 0 */
///     CUDA_CALL(cudaMemset(devResults, 0, 64 * 512 * sizeof(int)));
/// 
///     /* Allocate space for prng states on device */
///     CUDA_CALL(cudaMalloc((void **)&devMTGPStates, 64 * sizeof(curandStateMtgp32)));
///     
///     ////////////////////////////////////////////////////////////////////////
///     /* Allocate space for MTGP kernel parameters */
///     CUDA_CALL(cudaMalloc((void**)&devKernelParams, sizeof(mtgp32_kernel_params)));
///     
///     /* Reformat from predefined parameter sets to kernel format, */
///     /* and copy kernel parameters to device memory               */
///     CURAND_CALL(curandMakeMTGP32Constants(mtgp32dc_params_fast_11213, devKernelParams));
///     
///     /* Initialize one state per thread block */
///     CURAND_CALL(curandMakeMTGP32KernelState(devMTGPStates, 
///                 mtgp32dc_params_fast_11213, devKernelParams, 64, 1234));
///     ////////////////////////////////////////////////////////////////////////
///     
///     /* Generate and use pseudo-random  */
///     for(i = 0; i < 10; i++) {
///         generate_kernel<<<64, 512>>>(devMTGPStates, sampleCount, devResults);
///     }
/// 
///     /* Copy device memory to host */
///     CUDA_CALL(cudaMemcpy(
///         hostResults, devResults, 64 * 512 * sizeof(int), cudaMemcpyDeviceToHost)
///     );
/// 
///     /* Show result */
///     total = 0;
///     for(i = 0; i < 64 * 512; i++) {
///         total += hostResults[i];
///     }
///     
///     printf("Fraction with low bit set was %10.13g\n", 
///         (double)total / (64.0f * 512.0f * sampleCount * 10.0f));
/// 
///     /* Cleanup */
///     CUDA_CALL(cudaFree(devMTGPStates));
///     CUDA_CALL(cudaFree(devResults));
///     free(hostResults);
/// 
///     printf("OK\n");
///     return EXIT_SUCCESS;
/// }

int main(int argc, char * argv[])
{
    uint32_t i;
    uint32_t n = 1000000;

    curandGenerator_t gen;

    uint32_t * devData, * hostData;

    /* Allocate n uint32_ts on host */
    hostData = (uint32_t *)calloc(n, sizeof(uint32_t));

    /* Allocate n uint32_ts on device */
    CUDA_CALL(cudaMalloc((void **)&devData, n * sizeof(uint32_t)));

    /* Create pseudo-random number generator */
    CURAND_CALL(curandCreateGenerator(&gen, CURAND_RNG_PSEUDO_MTGP32));
    
    /* Set seed */
    CURAND_CALL(curandSetPseudoRandomGeneratorSeed(gen, 1234ULL));

    CURAND_CALL(curandGenerate(gen, devData, n));

    CUDA_CALL(cudaMemcpy(
        hostData, devData, n * sizeof(uint32_t), cudaMemcpyDeviceToHost
    ));

    for(i = 0; i < n; i++) {
        printf("%1.4f ", hostData[i]);
    }

    printf("\n");

    CURAND_CALL(curandDestroyGenerator(gen));
    CUDA_CALL(cudaFree(devData));
    free(hostData);    

    return EXIT_SUCCESS;
}

//int main(int argc, char *argv[])
//{
//    int i;
//    uint64_t total;
//    curandStateMtgp32 * devMTGPStates;
//    mtgp32_kernel_params * devKernelParams;
//
//    int * devResults, * hostResults;
//    int sampleCount = 10000;
//    
//    /* Allocate space for results on host */
//    hostResults = (int *)calloc(64 * 512, sizeof(int));
//
//    /* Allocate space for results on device */
//    CUDA_CALL(cudaMalloc((void **)&devResults, 64 * 512 * sizeof(int)));
//
//    /* Set results to 0 */
//    CUDA_CALL(cudaMemset(devResults, 0, 64 * 512 * sizeof(int)));
//
//    /* Allocate space for prng states on device */
//    CUDA_CALL(cudaMalloc((void **)&devMTGPStates, 64 * sizeof(curandStateMtgp32)));
//    
//    ////////////////////////////////////////////////////////////////////////
//    /* Allocate space for MTGP kernel parameters */
//    CUDA_CALL(cudaMalloc((void**)&devKernelParams, sizeof(mtgp32_kernel_params)));
//    
//    /* Reformat from predefined parameter sets to kernel format, */
//    /* and copy kernel parameters to device memory               */
//    CURAND_CALL(curandMakeMTGP32Constants(mtgp32dc_params_fast_11213, devKernelParams));
//    
//    /* Initialize one state per thread block */
//    CURAND_CALL(curandMakeMTGP32KernelState(devMTGPStates, 
//                mtgp32dc_params_fast_11213, devKernelParams, 64, 1234));
//    ////////////////////////////////////////////////////////////////////////
//    
//    /* Generate and use pseudo-random  */
//    for(i = 0; i < 10; i++) {
//        generate_kernel<<<64, 512>>>(devMTGPStates, sampleCount, devResults);
//    }
//
//    /* Copy device memory to host */
//    CUDA_CALL(cudaMemcpy(
//        hostResults, devResults, 64 * 512 * sizeof(int), cudaMemcpyDeviceToHost)
//    );
//
//    /* Show result */
//    total = 0;
//    for(i = 0; i < 64 * 512; i++) {
//        total += hostResults[i];
//    }
//    
//    printf("Fraction with low bit set was %10.13g\n", 
//        (double)total / (64.0f * 512.0f * sampleCount * 10.0f));
//
//    /* Cleanup */
//    CUDA_CALL(cudaFree(devMTGPStates));
//    CUDA_CALL(cudaFree(devResults));
//    free(hostResults);
//
//    printf("OK\n");
//    return EXIT_SUCCESS;
//}
