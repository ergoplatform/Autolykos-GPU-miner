// compaction.cu

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cuda.h>
#include <cuda_runtime.h>
#include <cooperative_groups.h>

#define CUDA_CALL(x) do { if((x) != cudaSuccess) { \
printf("CUDA error at %s:%d\n",__FILE__,__LINE__); \
return EXIT_FAILURE;}} while(0)

namespace cg = cooperative_groups;
#define NUM_ELEMS 1000000
#define NUM_THREADS_PER_BLOCK 512

// warp-aggregated atomic increment
__device__ int warpInc(
    uint32_t * c
) {
    cg::coalesced_group active = cg::coalesced_threads();
    uint32_t res = 0;

    if (!active.thread_rank()) res = atomicAdd(c, active.size());

    return active.shfl(res, 0) + active.thread_rank();
}

__global__ void compactify(
    const uint32_t * in,
    uint32_t inlen,
    uint32_t * out,
    uint32_t * c
) {
    uint32_t tid = threadIdx.x + blockIdx.x * blockDim.x;

    for (int i = tid; i < inlen; i += gridDim.x * blockDim.x)
    {
        if (in[i]) out[warpInc(c)] = in[i];
    }
}

int main(int argc, char **argv)
{
    uint32_t *data_to_filter;
    uint32_t *filtered_data;
    uint32_t nres = 0;
    uint32_t *d_data_to_filter;
    uint32_t *d_filtered_data;
    uint32_t *d_nres;

    data_to_filter = reinterpret_cast<uint32_t *>(malloc(sizeof(uint32_t) * NUM_ELEMS));

    // Generate input data.
    for (int i = 0; i < NUM_ELEMS; i++) {
        data_to_filter[i] = rand() % 20;
    }

    for (int i = 0; i < NUM_ELEMS / 10; i++) {
        data_to_filter[rand() % NUM_ELEMS] = 0;
    }
    //for (int i = 0; i < NUM_ELEMS; i++) {
    //    printf("%d ", data_to_filter[i]);
    //}
    //printf("\n\n");

    //findCudaDevice(argc, (const char **)argv);

    CUDA_CALL(cudaMalloc(&d_data_to_filter, sizeof(uint32_t) * NUM_ELEMS));
    CUDA_CALL(cudaMalloc(&d_filtered_data, sizeof(uint32_t) * NUM_ELEMS));
    CUDA_CALL(cudaMalloc(&d_nres, sizeof(uint32_t)));

    CUDA_CALL(cudaMemcpy(
        d_data_to_filter, data_to_filter, sizeof(uint32_t) * NUM_ELEMS,
        cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemset(d_nres, 0, sizeof(uint32_t)));

    dim3 dimBlock(NUM_THREADS_PER_BLOCK, 1, 1);
    dim3 dimGrid((NUM_ELEMS / NUM_THREADS_PER_BLOCK) + 1, 1, 1);

    compactify<<<dimGrid, dimBlock>>>(
        d_data_to_filter, NUM_ELEMS, d_filtered_data, d_nres
    );

    CUDA_CALL(
    cudaMemcpy(&nres, d_nres, sizeof(uint32_t), cudaMemcpyDeviceToHost));

    filtered_data = reinterpret_cast<uint32_t *>(malloc(sizeof(uint32_t) * nres));

    CUDA_CALL(cudaMemcpy(filtered_data, d_filtered_data, sizeof(uint32_t) * nres,
     cudaMemcpyDeviceToHost));

    uint32_t * host_filtered_data =
    reinterpret_cast<uint32_t *>(malloc(sizeof(uint32_t) * NUM_ELEMS));

    // Generate host output with host filtering code.
    uint32_t host_flt_count = 0;

    for (uint32_t i = 0; i < NUM_ELEMS; i++)
    {
        if (data_to_filter[i] > 0)
        {
            host_filtered_data[host_flt_count++] = data_to_filter[i];
        }
    }

    // printf("nres = %d\n", nres);

    for (uint32_t i = 0; i < NUM_ELEMS; i++)
    {
        if (i < nres && filtered_data[i] == 0)
        {
            printf("ERROR:");
        }
        // if (i == nres)
        // {
        //     printf("|| ");
        // }

        // printf("%d ", filtered_data[i]);
    }
    // printf("\n\n");

    for (uint32_t i = 0; i < NUM_ELEMS; i++)
    {
        // if (i == nres)
        // {
        //     printf("|| ");
        // }

        // printf("%d ", host_filtered_data[i]);
    }
    // printf("\n\n");

    printf("\nWarp Aggregated Atomics %s \n",
    host_flt_count == nres ? "PASSED" : "FAILED");

    CUDA_CALL(cudaFree(d_data_to_filter));
    CUDA_CALL(cudaFree(d_filtered_data));
    CUDA_CALL(cudaFree(d_nres));

    free(data_to_filter);
    free(filtered_data);
    free(host_filtered_data);
}

// compaction.cu
