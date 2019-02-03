#ifndef KERNEL_H
#define KERNEL_H

#include <stdint.h>
#include <stddef.h>

__global__ void addc(
    // 8 * 32 bits
    uint32_t * x,
    // 1 * 32 bits
    uint32_t * carry,
    // 8 * 32 bits
    uint32_t * y
);

__global__ void subc(
    // 8 * 32 bits
    uint32_t * x,
    // 1 * 32 bits
    uint32_t * carry,
    // 8 * 32 bits
    uint32_t * y
);

__global__ void mul(
    // 8 * 32 bits
    uint32_t * x,
    // 8 * 32 bits
    uint32_t * y,
    // 16 * 32 bits
    uint32_t * res
);

__global__ void mod_q(
    // word count
    uint32_t xw,
    // xw * 64 bits
    uint64_t * x
    // result 4 * 64 bits -> x[0, 1, 2, 3]
);

#endif // KERNEL_H
