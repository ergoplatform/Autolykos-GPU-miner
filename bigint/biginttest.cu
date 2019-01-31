#include <stdio.h>
#include <stdlib.h>
#include <cuda.h>

#include "kernel.h"

#define CUDA_CALL(x) do { if((x) != cudaSuccess) { \
printf("CUDA error at %s:%d\n",__FILE__,__LINE__); \
return EXIT_FAILURE;}} while(0)

/// 8 * 32 bits
/// q == [q0, q1, q2, q3, 0, 0, 0, 0x10000000]
/// 4 * 64 bits
/// q == [Q0, Q1, 0, 0x1000000000000000]

// 32 bits
#define q3 0x14def9de
#define q2 0xa2f79cd6
#define q1 0x5812631a
#define q0 0x5cf5d3ed

// 64 bits
#define Q1 0x14def9dea2f79cd6
#define Q0 0x5812631a5cf5d3ed

#define Q0_1 0x5812631a5cf5d3ec
#define Q0_2 0x5812631a5cf5d3eb
#define Q0_3 0x5812631a5cf5d3ea

int main(int argc, char *argv[])
{
    uint64_t * x_h = (uint64_t *)malloc(4 * sizeof(uint64_t));
    uint64_t * y_h = (uint64_t *)malloc(4 * sizeof(uint64_t));
    uint64_t * res_h = (uint64_t *)malloc(8 * sizeof(uint64_t));

    x_h[3] = 0x1000000000000000;
    x_h[2] = 0;
    x_h[1] = Q1;
    x_h[0] = Q0_1;

    y_h[3] = 0x1000000000000000;
    y_h[2] = 0;
    y_h[1] = Q1;
    y_h[0] = Q0_2;

    //x_h[3] = 0;
    //x_h[2] = 0;
    //x_h[1] = 0;
    //x_h[0] = 0x100;

    //y_h[3] = 0x1000000000000000;
    //y_h[2] = 0;
    //y_h[1] = Q1;
    //y_h[0] = Q0;

    uint32_t * x_d;
    uint32_t * y_d;
    uint64_t * res_d;
    
    CUDA_CALL(cudaMalloc((void **)&x_d, 8 * sizeof(uint32_t)));
    CUDA_CALL(cudaMalloc((void **)&y_d, 8 * sizeof(uint32_t)));
    CUDA_CALL(cudaMalloc((void **)&res_d, 8 * sizeof(uint64_t)));

    CUDA_CALL(cudaMemcpy(
        x_d, (uint32_t *)x_h, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice
    ));
    CUDA_CALL(cudaMemcpy(
        y_d, (uint32_t *)y_h, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice
    ));

    mul<<<1, 1>>>(x_d, y_d, (uint32_t *)res_d);
    mod_q<<<1, 1>>>(8, res_d);

    CUDA_CALL(cudaMemcpy(
        res_h, res_d, 8 * sizeof(uint64_t), cudaMemcpyDeviceToHost
    ));

    //printf("%#lx, %#lx,\n%#lx, %#lx\n", res_h[7], res_h[6], res_h[5], res_h[4]);
    printf("%#lx, %#lx,\n%#lx, %#lx\n", res_h[3], res_h[2], res_h[1], res_h[0]);

    printf("\n");

    CUDA_CALL(cudaFree(x_d));
    CUDA_CALL(cudaFree(y_d));
    CUDA_CALL(cudaFree(res_d));

    free(x_h);
    free(y_h);
    free(res_h);

    printf("OK\n");
    return EXIT_SUCCESS;
}

