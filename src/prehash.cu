// prehash.cu

#include "../include/prehash.h"
#include "../include/compaction.h"
#include <cuda.h>

////////////////////////////////////////////////////////////////////////////////
//  First iteration of hashes precalculation
////////////////////////////////////////////////////////////////////////////////
__global__ void initPrehash(
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    uint32_t * unfinalized
) {
    uint32_t j;
    uint32_t tid = threadIdx.x;

    // shared memory
    __shared__ uint32_t shared[2 * B_DIM];
    shared[2 * tid] = data[2 * tid];
    shared[2 * tid + 1] = data[2 * tid + 1];

    __syncthreads();

    // 8 * 64 bits = 64 bytes 
    uint64_t * blake2b_iv = (uint64_t *)shared;
    // 192 * 8 bits = 192 bytes 
    uint8_t * sigma = (uint8_t *)(shared + 16);
    //uint32_t * sk = shared + 64;
    // pk || mes || w
    uint32_t * rem = shared + 72;

    // local memory
    // 64 * 32 bits
    uint32_t local[64];

    // 16 * 64 bits = 128 bytes 
    uint64_t * v = (uint64_t *)local;
    // 16 * 64 bits = 128 bytes 
    uint64_t * m = v + 16;
    blake2b_ctx * ctx = (blake2b_ctx *)(local + 8);

    tid = threadIdx.x + blockDim.x * blockIdx.x;

    //====================================================================//
    //  Initialize context
    //====================================================================//
#pragma unroll
    for (j = 0; j < 8; ++j)
    {
        ctx->h[j] = blake2b_iv[j];
    }

    ctx->h[0] ^= 0x01010000 ^ (0 << 8) ^ NUM_BYTE_SIZE;

    ctx->t[0] = 0;
    ctx->t[1] = 0;
    ctx->c = 0;

#pragma unroll
    for (j = 0; j < 128; ++j)
    {
        ctx->b[j] = 0;
    }

    //====================================================================//
    //  Hash tid
    //====================================================================//
#pragma unroll
    for (j = 0; ctx->c < 128 && j < 4; ++j)
    {
        ctx->b[ctx->c++] = ((const uint8_t *)&tid)[j];
    }

#pragma unroll
    while (j < 4)
    {
        ctx->t[0] += ctx->c;
        ctx->t[1] += 1 - !(ctx->t[0] < ctx->c);

#pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            v[i] = ctx->h[i];
            v[i + 8] = blake2b_iv[i];
        }

        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[1];

#pragma unroll
        for (int i = 0; i < 16; i++)
        {
            m[i] = B2B_GET64(&ctx->b[8 * i]);
        }

#pragma unroll
        for (int i = 0; i < 192; i += 16)
        {
            B2B_G(0, 4,  8, 12, m[sigma[i +  0]], m[sigma[i +  1]]);
            B2B_G(1, 5,  9, 13, m[sigma[i +  2]], m[sigma[i +  3]]);
            B2B_G(2, 6, 10, 14, m[sigma[i +  4]], m[sigma[i +  5]]);
            B2B_G(3, 7, 11, 15, m[sigma[i +  6]], m[sigma[i +  7]]);
            B2B_G(0, 5, 10, 15, m[sigma[i +  8]], m[sigma[i +  9]]);
            B2B_G(1, 6, 11, 12, m[sigma[i + 10]], m[sigma[i + 11]]);
            B2B_G(2, 7,  8, 13, m[sigma[i + 12]], m[sigma[i + 13]]);
            B2B_G(3, 4,  9, 14, m[sigma[i + 14]], m[sigma[i + 15]]);
        }

#pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            ctx->h[i] ^= v[i] ^ v[i + 8];
        }

        ctx->c = 0;
       
#pragma unroll
        while (ctx->c < 128 && j < 4)
        {
            ctx->b[ctx->c++] = ((const uint8_t *)tid)[j++];
        }
    }

    //====================================================================//
    //  Hash constant message
    //====================================================================//
    for (j = 0; ctx->c < 128 && j < 0x1000; ++j)
    {
        ctx->b[ctx->c++] = !(j & 3) * (j >> 2);
    }

    while (j < 0x1000)
    {
        ctx->t[0] += ctx->c;
        ctx->t[1] += 1 - !(ctx->t[0] < ctx->c);

#pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            v[i] = ctx->h[i];
            v[i + 8] = blake2b_iv[i];
        }

        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[1];

#pragma unroll
        for (int i = 0; i < 16; i++)
        {
            m[i] = B2B_GET64(&ctx->b[8 * i]);
        }

#pragma unroll
        for (int i = 0; i < 192; i += 16)
        {
            B2B_G(0, 4,  8, 12, m[sigma[i +  0]], m[sigma[i +  1]]);
            B2B_G(1, 5,  9, 13, m[sigma[i +  2]], m[sigma[i +  3]]);
            B2B_G(2, 6, 10, 14, m[sigma[i +  4]], m[sigma[i +  5]]);
            B2B_G(3, 7, 11, 15, m[sigma[i +  6]], m[sigma[i +  7]]);
            B2B_G(0, 5, 10, 15, m[sigma[i +  8]], m[sigma[i +  9]]);
            B2B_G(1, 6, 11, 12, m[sigma[i + 10]], m[sigma[i + 11]]);
            B2B_G(2, 7,  8, 13, m[sigma[i + 12]], m[sigma[i + 13]]);
            B2B_G(3, 4,  9, 14, m[sigma[i + 14]], m[sigma[i + 15]]);
        }

#pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            ctx->h[i] ^= v[i] ^ v[i + 8];
        }

        ctx->c = 0;
       
        for ( ; ctx->c < 128 && j < 0x1000; ++j)
        {
            ctx->b[ctx->c++] = !(j & 3) * (j >> 2);
        }
    }

    //====================================================================//
    //  Hash public key, message & one-time public key
    //====================================================================//
    for (j = 0; ctx->c < 128 && j < 3 * NUM_BYTE_SIZE; ++j)
    {
        ctx->b[ctx->c++] = ((const uint8_t *)rem)[j];
    }

    while (j < 3 * NUM_BYTE_SIZE)
    {
        ctx->t[0] += ctx->c;
        ctx->t[1] += 1 - !(ctx->t[0] < ctx->c);

#pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            v[i] = ctx->h[i];
            v[i + 8] = blake2b_iv[i];
        }

        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[1];

#pragma unroll
        for (int i = 0; i < 16; i++)
        {
            m[i] = B2B_GET64(&ctx->b[8 * i]);
        }

#pragma unroll
        for (int i = 0; i < 192; i += 16)
        {
            B2B_G(0, 4,  8, 12, m[sigma[i +  0]], m[sigma[i +  1]]);
            B2B_G(1, 5,  9, 13, m[sigma[i +  2]], m[sigma[i +  3]]);
            B2B_G(2, 6, 10, 14, m[sigma[i +  4]], m[sigma[i +  5]]);
            B2B_G(3, 7, 11, 15, m[sigma[i +  6]], m[sigma[i +  7]]);
            B2B_G(0, 5, 10, 15, m[sigma[i +  8]], m[sigma[i +  9]]);
            B2B_G(1, 6, 11, 12, m[sigma[i + 10]], m[sigma[i + 11]]);
            B2B_G(2, 7,  8, 13, m[sigma[i + 12]], m[sigma[i + 13]]);
            B2B_G(3, 4,  9, 14, m[sigma[i + 14]], m[sigma[i + 15]]);
        }

#pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            ctx->h[i] ^= v[i] ^ v[i + 8];
        }

        ctx->c = 0;
       
        while (ctx->c < 128 && j < 3 * NUM_BYTE_SIZE)
        {
            ctx->b[ctx->c++] = ((const uint8_t *)rem)[j++];
        }
    }

    //====================================================================//
    //  Finalize hash
    //====================================================================//
    ctx->t[0] += ctx->c;
    ctx->t[1] += 1 - !(ctx->t[0] < ctx->c);

    while (ctx->c < 128)
    {
        ctx->b[ctx->c++] = 0;
    }

#pragma unroll
    for (int i = 0; i < 8; ++i)
    {
        v[i] = ctx->h[i];
        v[i + 8] = blake2b_iv[i];
    }

    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    v[14] = ~v[14];

#pragma unroll
    for (int i = 0; i < 16; i++)
    {
        m[i] = B2B_GET64(&ctx->b[8 * i]);
    }

#pragma unroll
    for (int i = 0; i < 192; i += 16)
    {
        B2B_G(0, 4,  8, 12, m[sigma[i +  0]], m[sigma[i +  1]]);
        B2B_G(1, 5,  9, 13, m[sigma[i +  2]], m[sigma[i +  3]]);
        B2B_G(2, 6, 10, 14, m[sigma[i +  4]], m[sigma[i +  5]]);
        B2B_G(3, 7, 11, 15, m[sigma[i +  6]], m[sigma[i +  7]]);
        B2B_G(0, 5, 10, 15, m[sigma[i +  8]], m[sigma[i +  9]]);
        B2B_G(1, 6, 11, 12, m[sigma[i + 10]], m[sigma[i + 11]]);
        B2B_G(2, 7,  8, 13, m[sigma[i + 12]], m[sigma[i + 13]]);
        B2B_G(3, 4,  9, 14, m[sigma[i + 14]], m[sigma[i + 15]]);
    }

#pragma unroll
    for (int i = 0; i < 8; ++i)
    {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }

#pragma unroll
    for (j = 0; j < NUM_BYTE_SIZE; ++j)
    {
        ((uint8_t *)local)[j] = (ctx->h[j >> 3] >> ((j & 7) << 3)) & 0xFF;
    }

    //===================================================================//
    //  Dump hashult to global memory
    //===================================================================//
    j = ((uint64_t *)local)[3] <= FQ3 && ((uint64_t *)local)[2] <= FQ2
        && ((uint64_t *)local)[1] <= FQ1 && ((uint64_t *)local)[0] <= FQ0;

    unfinalized[tid] = (1 - !j) * (tid + 1);

#pragma unroll
    for (int i = 0; i < 8; ++i)
    {
        hash[(tid << 3) + i] = local[i];
    }
}

////////////////////////////////////////////////////////////////////////////////
//  Unfinalized hashes update
////////////////////////////////////////////////////////////////////////////////
__global__ void updatePrehash(
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    uint32_t * unfinalized
) {
    uint32_t j;
    uint32_t tid = threadIdx.x;

    // shared memory
    __shared__ uint32_t shared[2 * B_DIM];
    shared[2 * tid] = data[2 * tid];
    shared[2 * tid + 1] = data[2 * tid + 1];

    __syncthreads();

    // 8 * 64 bits = 64 bytes 
    uint64_t * blake2b_iv = (uint64_t *)shared;
    // 192 * 8 bits = 192 bytes 
    uint8_t * sigma = (uint8_t *)(shared + 16);

    // local memory
    // 64 * 32 bits
    uint32_t local[64];

    // 16 * 64 bits = 128 bytes 
    uint64_t * v = (uint64_t *)local;
    // 16 * 64 bits = 128 bytes 
    uint64_t * m = v + 16;
    blake2b_ctx * ctx = (blake2b_ctx *)(local + 8);

    tid = threadIdx.x + blockDim.x * blockIdx.x;
    uint32_t addr = unfinalized[tid] - 1;

    //====================================================================//
    //  Initialize context
    //====================================================================//
#pragma unroll
    for (j = 0; j < 8; ++j)
    {
        ctx->h[j] = blake2b_iv[j];
    }

    ctx->h[0] ^= 0x01010000 ^ (0 << 8) ^ NUM_BYTE_SIZE;

    ctx->t[0] = 0;
    ctx->t[1] = 0;
    ctx->c = 0;

#pragma unroll
    for (j = 0; j < 128; ++j)
    {
        ctx->b[j] = 0;
    }

    //====================================================================//
    //  Hash previous hash
    //====================================================================//
    for (j = 0; ctx->c < 128 && j < NUM_BYTE_SIZE; ++j)
    {
        ctx->b[ctx->c++]
            = ((const uint8_t *)(hash + (addr << 3)))[j];
    }

    while (j < NUM_BYTE_SIZE)
    {
        ctx->t[0] += ctx->c;
        ctx->t[1] += 1 - !(ctx->t[0] < ctx->c);

#pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            v[i] = ctx->h[i];
            v[i + 8] = blake2b_iv[i];
        }

        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[1];

#pragma unroll
        for (int i = 0; i < 16; i++)
        {
            m[i] = B2B_GET64(&ctx->b[8 * i]);
        }

#pragma unroll
        for (int i = 0; i < 192; i += 16)
        {
            B2B_G(0, 4,  8, 12, m[sigma[i +  0]], m[sigma[i +  1]]);
            B2B_G(1, 5,  9, 13, m[sigma[i +  2]], m[sigma[i +  3]]);
            B2B_G(2, 6, 10, 14, m[sigma[i +  4]], m[sigma[i +  5]]);
            B2B_G(3, 7, 11, 15, m[sigma[i +  6]], m[sigma[i +  7]]);
            B2B_G(0, 5, 10, 15, m[sigma[i +  8]], m[sigma[i +  9]]);
            B2B_G(1, 6, 11, 12, m[sigma[i + 10]], m[sigma[i + 11]]);
            B2B_G(2, 7,  8, 13, m[sigma[i + 12]], m[sigma[i + 13]]);
            B2B_G(3, 4,  9, 14, m[sigma[i + 14]], m[sigma[i + 15]]);
        }

#pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            ctx->h[i] ^= v[i] ^ v[i + 8];
        }

        ctx->c = 0;
       
        while (ctx->c < 128 && j < NUM_BYTE_SIZE)
        {
            ctx->b[ctx->c++]
                = ((const uint8_t *)(hash + (addr << 3)))[j++];
        }
    }

    //====================================================================//
    //  Finalize hash
    //====================================================================//
    ctx->t[0] += ctx->c;
    ctx->t[1] += 1 - !(ctx->t[0] < ctx->c);

    while (ctx->c < 128)
    {
        ctx->b[ctx->c++] = 0;
    }

#pragma unroll
    for (int i = 0; i < 8; ++i)
    {
        v[i] = ctx->h[i];
        v[i + 8] = blake2b_iv[i];
    }

    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    v[14] = ~v[14];

#pragma unroll
    for (int i = 0; i < 16; i++)
    {
        m[i] = B2B_GET64(&ctx->b[8 * i]);
    }

#pragma unroll
    for (int i = 0; i < 192; i += 16)
    {
        B2B_G(0, 4,  8, 12, m[sigma[i +  0]], m[sigma[i +  1]]);
        B2B_G(1, 5,  9, 13, m[sigma[i +  2]], m[sigma[i +  3]]);
        B2B_G(2, 6, 10, 14, m[sigma[i +  4]], m[sigma[i +  5]]);
        B2B_G(3, 7, 11, 15, m[sigma[i +  6]], m[sigma[i +  7]]);
        B2B_G(0, 5, 10, 15, m[sigma[i +  8]], m[sigma[i +  9]]);
        B2B_G(1, 6, 11, 12, m[sigma[i + 10]], m[sigma[i + 11]]);
        B2B_G(2, 7,  8, 13, m[sigma[i + 12]], m[sigma[i + 13]]);
        B2B_G(3, 4,  9, 14, m[sigma[i + 14]], m[sigma[i + 15]]);
    }

#pragma unroll
    for (int i = 0; i < 8; ++i)
    {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }

    for (j = 0; j < NUM_BYTE_SIZE; ++j)
    {
        ((uint8_t *)local)[j] = (ctx->h[j >> 3] >> ((j & 7) << 3)) & 0xFF;
    }
    //===================================================================//
    //  Dump hashult to global memory
    //===================================================================//
    j = ((uint64_t *)local)[3] <= FQ3 && ((uint64_t *)local)[2] <= FQ2
        && ((uint64_t *)local)[1] <= FQ1 && ((uint64_t *)local)[0] <= FQ0;

    unfinalized[tid] *= 1 - !j;

#pragma unroll
    for (int i = 0; i < 8; ++i)
    {
        hash[(addr << 3) + i] = local[i];
    }
}

////////////////////////////////////////////////////////////////////////////////
//  Hashes by secret key multiplication mod q 
////////////////////////////////////////////////////////////////////////////////
__global__ void finalizePrehash(
    const uint32_t * data,
    // hashes
    uint32_t * hash
) {
    uint32_t tid = threadIdx.x;

    // shared memory
    __shared__ uint32_t shared[B_DIM];
    shared[tid] = data[tid + 64];
    __syncthreads();
    // 8 * 32 bits = 32 bytes
    uint32_t * sk = shared;

    // local memory
    uint32_t r[18];
    r[16] = r[17] = 0;

    tid = threadIdx.x + blockDim.x * blockIdx.x;
    uint32_t * x = hash + (tid << 3); 

    //====================================================================//
    //  x[0] * y -> r[0, ..., 7, 8]
    //====================================================================//
    // initialize r[0, ..., 7]
#pragma unroll
    for (int j = 0; j < 8; j += 2)
    {
        asm volatile (
            "mul.lo.u32 %0, %1, %2;": "=r"(r[j]): "r"(x[0]), "r"(sk[j])
        );
        asm volatile (
            "mul.hi.u32 %0, %1, %2;": "=r"(r[j + 1]): "r"(x[0]), "r"(sk[j])
        );
    }

    //====================================================================//
    asm volatile (
        "mad.lo.cc.u32 %0, %1, %2, %0;": "+r"(r[1]): "r"(x[0]), "r"(sk[1])
    );
    asm volatile (
        "madc.hi.cc.u32 %0, %1, %2, %0;": "+r"(r[2]): "r"(x[0]), "r"(sk[1])
    );

#pragma unroll
    for (int j = 3; j < 6; j += 2)
    {
        asm volatile (
            "madc.lo.cc.u32 %0, %1, %2, %0;": "+r"(r[j]): "r"(x[0]), "r"(sk[j])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(r[j + 1]): "r"(x[0]), "r"(sk[j])
        );
    }

    asm volatile (
        "madc.lo.cc.u32 %0, %1, %2, %0;": "+r"(r[7]): "r"(x[0]), "r"(sk[7])
    );
    // initialize r[8]
    asm volatile (
        "madc.hi.u32 %0, %1, %2, 0;": "=r"(r[8]): "r"(x[0]), "r"(sk[7])
    );

    //====================================================================//
    //  x[i] * sk -> r[i, ..., i + 7, i + 8]
    //====================================================================//
#pragma unroll
    for (int i = 1; i < 8; ++i)
    {
        asm volatile (
            "mad.lo.cc.u32 %0, %1, %2, %0;": "+r"(r[i]): "r"(x[i]), "r"(sk[0])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(r[i + 1]): "r"(x[i]), "r"(sk[0])
        );

#pragma unroll
        for (int j = 2; j < 8; j += 2)
        {
            asm volatile (
                "madc.lo.cc.u32 %0, %1, %2, %0;":
                "+r"(r[i + j]): "r"(x[i]), "r"(sk[j])
            );
            asm volatile (
                "madc.hi.cc.u32 %0, %1, %2, %0;":
                "+r"(r[i + j + 1]): "r"(x[i]), "r"(sk[j])
            );
        }

    // initialize r[i + 8]
        asm volatile (
            "addc.u32 %0, 0, 0;": "=r"(r[i + 8])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, %2, %0;":
            "+r"(r[i + 1]): "r"(x[i]), "r"(sk[1])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(r[i + 2]): "r"(x[i]), "r"(sk[1])
        );

#pragma unroll
        for (int j = 3; j < 6; j += 2)
        {
            asm volatile (
                "madc.lo.cc.u32 %0, %1, %2, %0;":
                "+r"(r[i + j]): "r"(x[i]), "r"(sk[j])
            );
            asm volatile (
                "madc.hi.cc.u32 %0, %1, %2, %0;":
                "+r"(r[i + j + 1]): "r"(x[i]), "r"(sk[j])
            );
        }

        asm volatile (
            "madc.lo.cc.u32 %0, %1, %2, %0;":
            "+r"(r[i + 7]): "r"(x[i]), "r"(sk[7])
        );
        asm volatile (
            "madc.hi.u32 %0, %1, %2, %0;":
            "+r"(r[i + 8]): "r"(x[i]), "r"(sk[7])
        );
    }

    //====================================================================//
    //  mod q
    //====================================================================//
    uint64_t * y = (uint64_t *)r; 
    uint32_t d[2]; 
    uint32_t med[6];
    uint32_t carry;

    for (int i = 16; i >= 8; i -= 2)
    {
        *((uint64_t *)d) = ((y[i >> 1] << 4) | (y[(i >> 1) - 1] >> 60))
            - (y[i >> 1] >> 60);

        // correct highest 32 bits
        r[i - 1] = (r[i - 1] & 0x0FFFFFFF) | r[i + 1] & 0x10000000;

    //====================================================================//
    //  d * q -> med[0, ..., 5]
    //====================================================================//
        asm volatile (
            "mul.lo.u32 %0, %1, "q0_s";": "=r"(med[0]): "r"(d[0])
        );
        asm volatile (
            "mul.hi.u32 %0, %1, "q0_s";": "=r"(med[1]): "r"(d[0])
        );
        asm volatile (
            "mul.lo.u32 %0, %1, "q2_s";": "=r"(med[2]): "r"(d[0])
        );
        asm volatile (
            "mul.hi.u32 %0, %1, "q2_s";": "=r"(med[3]): "r"(d[0])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q1_s", %0;": "+r"(med[1]): "r"(d[0])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, "q1_s", %0;": "+r"(med[2]): "r"(d[0])
        );
        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;": "+r"(med[3]): "r"(d[0])
        );
        asm volatile (
            "madc.hi.u32 %0, %1, "q3_s", 0;": "=r"(med[4]): "r"(d[0])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q0_s", %0;": "+r"(med[1]): "r"(d[1])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, "q0_s", %0;": "+r"(med[2]): "r"(d[1])
        );
        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q2_s", %0;": "+r"(med[3]): "r"(d[1])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1," q2_s", %0;": "+r"(med[4]): "r"(d[1])
        );
        asm volatile (
            "addc.u32 %0, 0, 0;": "=r"(med[5])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q1_s", %0;": "+r"(med[2]): "r"(d[1])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, "q1_s", %0;": "+r"(med[3]): "r"(d[1])
        );
        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;": "+r"(med[4]): "r"(d[1])
        );
        asm volatile (
            "madc.hi.u32 %0, %1, "q3_s", %0;": "+r"(med[5]): "r"(d[1])
        );

    //====================================================================//
    //  r[i/2 - 2, i/2 - 3, i/2 - 4] mod q
    //====================================================================//
        asm volatile (
            "sub.cc.u32 %0, %0, %1;": "+r"(r[i - 8]): "r"(med[0])
        );

#pragma unroll
        for (int j = 1; j < 6; ++j)
        {
            asm volatile (
                "subc.cc.u32 %0, %0, %1;": "+r"(r[i + j - 8]): "r"(med[j])
            );
        }

        asm volatile (
            "subc.cc.u32 %0, %0, 0;": "+r"(r[i - 2])
        );

        asm volatile (
            "subc.cc.u32 %0, %0, 0;": "+r"(r[i - 1])
        );

    //====================================================================//
    //  r[i/2 - 2, i/2 - 3, i/2 - 4] correction
    //====================================================================//
        asm volatile (
            "subc.u32 %0, 0, 0;": "=r"(carry)
        );

        carry = 0 - carry;

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q0_s", %0;": "+r"(r[i - 8]): "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q1_s", %0;": "+r"(r[i - 7]): "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q2_s", %0;": "+r"(r[i - 6]): "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;": "+r"(r[i - 5]): "r"(carry)
        );

    //====================================================================//
#pragma unroll
        for (int j = 0; j < 3; ++j)
        {
            asm volatile (
                "addc.cc.u32 %0, %0, 0;": "+r"(r[i + j - 4])
            );
        }

        asm volatile (
            "addc.u32 %0, %0, 0;": "+r"(r[i - 1])
        );
    }

    //===================================================================//
    //  Dump result to global memory
    //===================================================================//
#pragma unroll
    for (int i = 0; i < 8; ++i)
    {
        hash[(tid << 3) + i] = r[i];
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Precalculate hashes
////////////////////////////////////////////////////////////////////////////////
int prehash(
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    // indices of out of bounds hashes
    uint32_t * indices
) {
    uint32_t len = N_LEN;

    // hash index, constant message and public key
    initPrehash<<<1 + (N_LEN - 1) / B_DIM, B_DIM>>>(data, hash, indices);

    // determine indices of out of bounds hashes
    compactify<<<1 + (N_LEN - 1) / B_DIM, B_DIM>>>(
        indices, len, indices + N_LEN, indices + 2 * N_LEN
    );

    CUDA_CALL(cudaMemcpy(
        (void *)&len, (void *)(indices + 2 * N_LEN), 4, cudaMemcpyDeviceToHost
    ));

    while (len)
    {
        // rehash out of bounds hashes
        updatePrehash<<<1 + (len - 1) / B_DIM, B_DIM>>>(data, hash, indices);

        // determine indices of out of bounds hashes
        compactify<<<1 + (len - 1) / B_DIM, B_DIM>>>(
            indices, len, indices + N_LEN, indices + 2 * N_LEN
        );

        CUDA_CALL(cudaMemcpy(
            (void *)&len, (void *)(indices + 2 * N_LEN),
            4, cudaMemcpyDeviceToHost
        ));
    }

    // multiply by secret key moq q
    finalizePrehash<<<1 + (N_LEN - 1) / B_DIM, B_DIM>>>(data, hash);

    return 0;
}

// prehash.cu
