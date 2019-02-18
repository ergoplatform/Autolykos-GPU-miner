// prehash.cu

#include "../include/prehash.h"
#include "../include/compaction.h"
#include <cuda.h>

////////////////////////////////////////////////////////////////////////////////
//  First iteration of hashes precalculation
////////////////////////////////////////////////////////////////////////////////
__global__ void initPrehash(
    // data: pk || mes || w || x || sk
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid
) {
    uint32_t j;
    uint32_t tid = threadIdx.x;

    // shared memory
    __shared__ uint32_t sdata[B_DIM];

    sdata[tid] = data[tid];
    __syncthreads();

    // pk || mes || w
    // 3 * NUM_SIZE_8 bytes
    uint32_t * rem = sdata;

    // local memory
    // 472 bytes
    uint32_t ldata[118];

    // 32 * 64 bits = 256 bytes 
    uint64_t * aux = (uint64_t *)ldata;
    // (212 + 4) bytes 
    blake2b_ctx * ctx = (blake2b_ctx *)(ldata + 64);

    tid += blockDim.x * blockIdx.x;

    //====================================================================//
    //  Initialize context
    //====================================================================//
    B2B_IV(ctx->h);

    ctx->h[0] ^= 0x01010000 ^ (0 << 8) ^ NUM_SIZE_8;
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

/// never reached /// #pragma unroll
/// never reached ///     for ( ; j < 4; )
/// never reached ///     {
/// never reached ///         B2B_H(ctx, aux);
/// never reached ///        
/// never reached /// #pragma unroll
/// never reached ///         for ( ; ctx->c < 128 && j < 4; ++j)
/// never reached ///         {
/// never reached ///             ctx->b[ctx->c++] = ((const uint8_t *)tid)[j];
/// never reached ///         }
/// never reached ///     }

    //====================================================================//
    //  Hash constant message
    //====================================================================//
    for (j = 0; ctx->c < 128 && j < 0x1000; ++j)
    {
        ctx->b[ctx->c++] = !(j & 3) * (j >> 2);
    }

    while (j < 0x1000)
    {
        B2B_H(ctx, aux);
       
        for ( ; ctx->c < 128 && j < 0x1000; ++j)
        {
            ctx->b[ctx->c++] = !(j & 3) * (j >> 2);
        }
    }

    //====================================================================//
    //  Hash public key, message & one-time public key
    //====================================================================//
    for (j = 0; ctx->c < 128 && j < 3 * NUM_SIZE_8; ++j)
    {
        ctx->b[ctx->c++] = ((const uint8_t *)rem)[j];
    }

    while (j < 3 * NUM_SIZE_8)
    {
        B2B_H(ctx, aux);
       
        while (ctx->c < 128 && j < 3 * NUM_SIZE_8)
        {
            ctx->b[ctx->c++] = ((const uint8_t *)rem)[j++];
        }
    }

    //====================================================================//
    //  Finalize hash
    //====================================================================//
    B2B_H_LAST(ctx, aux);

#pragma unroll
    for (j = 0; j < NUM_SIZE_8; ++j)
    {
        ((uint8_t *)ldata)[j] = (ctx->h[j >> 3] >> ((j & 7) << 3)) & 0xFF;
    }

    //===================================================================//
    //  Dump result to global memory
    //===================================================================//
    j = ((uint64_t *)ldata)[3] <= FQ3 && ((uint64_t *)ldata)[2] <= FQ2
        && ((uint64_t *)ldata)[1] <= FQ1 && ((uint64_t *)ldata)[0] <= FQ0;

    invalid[tid] = (1 - !j) * (tid + 1);

#pragma unroll
    for (int i = 0; i < NUM_SIZE_32; ++i)
    {
        hash[tid * NUM_SIZE_32 + i] = ldata[i];
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Rehash the out of bounds hash
////////////////////////////////////////////////////////////////////////////////
__global__ void updatePrehash(
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid
) {
    uint32_t j;
    uint32_t tid = threadIdx.x + blockDim.x * blockIdx.x;
    uint32_t addr = invalid[tid] - 1;

    // ldata memory
    // 472 bytes
    uint32_t ldata[118];

    // 32 * 64 bits = 256 bytes 
    uint64_t * aux = (uint64_t *)ldata;
    // (212 + 4) bytes 
    blake2b_ctx * ctx = (blake2b_ctx *)(ldata + 64);

    //====================================================================//
    //  Initialize context
    //====================================================================//
    B2B_IV(ctx->h);

    ctx->h[0] ^= 0x01010000 ^ (0 << 8) ^ NUM_SIZE_8;
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
#pragma unroll
    for (j = 0; ctx->c < 128 && j < NUM_SIZE_8; ++j)
    {
        ctx->b[ctx->c++] = ((const uint8_t *)(hash + addr * NUM_SIZE_32))[j];
    }

#pragma unroll
    for ( ; j < NUM_SIZE_8; )
    {
        B2B_H(ctx, aux);
       
#pragma unroll
        for ( ; ctx->c < 128 && j < NUM_SIZE_8; ++j)
        {
            ctx->b[ctx->c++]
                = ((const uint8_t *)(hash + addr * NUM_SIZE_32))[j];
        }
    }

    //====================================================================//
    //  Finalize hash
    //====================================================================//
    B2B_H_LAST(ctx, aux);

#pragma unroll
    for (j = 0; j < NUM_SIZE_8; ++j)
    {
        ((uint8_t *)ldata)[j] = (ctx->h[j >> 3] >> ((j & 7) << 3)) & 0xFF;
    }

    //===================================================================//
    //  Dump result to global memory
    //===================================================================//
    j = ((uint64_t *)ldata)[3] <= FQ3 && ((uint64_t *)ldata)[2] <= FQ2
        && ((uint64_t *)ldata)[1] <= FQ1 && ((uint64_t *)ldata)[0] <= FQ0;

    invalid[tid] *= 1 - !j;

#pragma unroll
    for (int i = 0; i < NUM_SIZE_32; ++i)
    {
        hash[addr * NUM_SIZE_32 + i] = ldata[i];
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Hashes multiplication mod q by one time secret key 
////////////////////////////////////////////////////////////////////////////////
__global__ void finalizePrehash(
    // data: pk || mes || w || x || sk
    const uint32_t * data,
    // hashes
    uint32_t * hash
) {
    uint32_t tid = threadIdx.x;

    // shared memory
    __shared__ uint32_t sdata[B_DIM];

    sdata[tid] = data[tid + 3 * NUM_SIZE_32];
    __syncthreads();

    // x
    // NUM_SIZE_8 bytes
    uint32_t * x = sdata;

    // local memory
    uint32_t r[18];
    r[16] = r[17] = 0;

    uint32_t * h = hash + tid * NUM_SIZE_32; 

    tid += blockDim.x * blockIdx.x;

    //====================================================================//
    //  h[0] * y -> r[0, ..., 7, 8]
    //====================================================================//
    // initialize r[0, ..., 7]
#pragma unroll
    for (int j = 0; j < 8; j += 2)
    {
        asm volatile (
            "mul.lo.u32 %0, %1, %2;": "=r"(r[j]): "r"(h[0]), "r"(x[j])
        );
        asm volatile (
            "mul.hi.u32 %0, %1, %2;": "=r"(r[j + 1]): "r"(h[0]), "r"(x[j])
        );
    }

    //====================================================================//
    asm volatile (
        "mad.lo.cc.u32 %0, %1, %2, %0;": "+r"(r[1]): "r"(h[0]), "r"(x[1])
    );
    asm volatile (
        "madc.hi.cc.u32 %0, %1, %2, %0;": "+r"(r[2]): "r"(h[0]), "r"(x[1])
    );

#pragma unroll
    for (int j = 3; j < 6; j += 2)
    {
        asm volatile (
            "madc.lo.cc.u32 %0, %1, %2, %0;": "+r"(r[j]): "r"(h[0]), "r"(x[j])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(r[j + 1]): "r"(h[0]), "r"(x[j])
        );
    }

    asm volatile (
        "madc.lo.cc.u32 %0, %1, %2, %0;": "+r"(r[7]): "r"(h[0]), "r"(x[7])
    );
    // initialize r[8]
    asm volatile (
        "madc.hi.u32 %0, %1, %2, 0;": "=r"(r[8]): "r"(h[0]), "r"(x[7])
    );

    //====================================================================//
    //  h[i] * x -> r[i, ..., i + 7, i + 8]
    //====================================================================//
#pragma unroll
    for (int i = 1; i < 8; ++i)
    {
        asm volatile (
            "mad.lo.cc.u32 %0, %1, %2, %0;": "+r"(r[i]): "r"(h[i]), "r"(x[0])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(r[i + 1]): "r"(h[i]), "r"(x[0])
        );

#pragma unroll
        for (int j = 2; j < 8; j += 2)
        {
            asm volatile (
                "madc.lo.cc.u32 %0, %1, %2, %0;":
                "+r"(r[i + j]): "r"(h[i]), "r"(x[j])
            );
            asm volatile (
                "madc.hi.cc.u32 %0, %1, %2, %0;":
                "+r"(r[i + j + 1]): "r"(h[i]), "r"(x[j])
            );
        }

    // initialize r[i + 8]
        asm volatile (
            "addc.u32 %0, 0, 0;": "=r"(r[i + 8])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, %2, %0;":
            "+r"(r[i + 1]): "r"(h[i]), "r"(x[1])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(r[i + 2]): "r"(h[i]), "r"(x[1])
        );

#pragma unroll
        for (int j = 3; j < 6; j += 2)
        {
            asm volatile (
                "madc.lo.cc.u32 %0, %1, %2, %0;":
                "+r"(r[i + j]): "r"(h[i]), "r"(x[j])
            );
            asm volatile (
                "madc.hi.cc.u32 %0, %1, %2, %0;":
                "+r"(r[i + j + 1]): "r"(h[i]), "r"(x[j])
            );
        }

        asm volatile (
            "madc.lo.cc.u32 %0, %1, %2, %0;":
            "+r"(r[i + 7]): "r"(h[i]), "r"(x[7])
        );
        asm volatile (
            "madc.hi.u32 %0, %1, %2, %0;":
            "+r"(r[i + 8]): "r"(h[i]), "r"(x[7])
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
    for (int i = 0; i < NUM_SIZE_32; ++i)
    {
        hash[tid * NUM_SIZE_32 + i] = r[i];
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Precalculate hashes
////////////////////////////////////////////////////////////////////////////////
int prehash(
    // data: pk || mes || w || x || sk
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid
) {
    uint32_t len = N_LEN;

    // hash index, constant message and public key
    initPrehash<<<1 + (N_LEN - 1) / B_DIM, B_DIM>>>(data, hash, invalid);

    // determine indices of out of bounds hashes
    compactify<<<1 + (N_LEN - 1) / B_DIM, B_DIM>>>(
        invalid, len, invalid + N_LEN, invalid + 2 * N_LEN
    );

    CUDA_CALL(cudaMemcpy(
        (void *)&len, (void *)(invalid + 2 * N_LEN), 4, cudaMemcpyDeviceToHost
    ));

    while (len)
    {
        // rehash out of bounds hashes
        updatePrehash<<<1 + (len - 1) / B_DIM, B_DIM>>>(hash, invalid);

        // determine indices of out of bounds hashes
        compactify<<<1 + (len - 1) / B_DIM, B_DIM>>>(
            invalid, len, invalid + N_LEN, invalid + 2 * N_LEN
        );

        CUDA_CALL(cudaMemcpy(
            (void *)&len, (void *)(invalid + 2 * N_LEN),
            4, cudaMemcpyDeviceToHost
        ));
    }

    // multiply by secret key moq q
    finalizePrehash<<<1 + (N_LEN - 1) / B_DIM, B_DIM>>>(data, hash);

    return 0;
}

// prehash.cu
