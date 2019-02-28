// prehash.cu

/*******************************************************************************

    PREHASH -- precalculation of hashes

*******************************************************************************/

#include "../include/prehash.h"
#include "../include/compaction.h"
#include <cuda.h>

#include <inttypes.h>

////////////////////////////////////////////////////////////////////////////////
//  First iteration of hashes precalculation
////////////////////////////////////////////////////////////////////////////////
__global__ void initPrehash(
    // data: pk || mes || w || padding || x || sk
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
    // 2 * PK_SIZE_8 + NUM_SIZE_8 bytes
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
        ctx->b[ctx->c++] = ((const uint8_t *)&tid)[3 - j];
    }

    //====================================================================//
    //  Hash constant message
    //====================================================================//
    for (j = 0; ctx->c < 128 && j < 0x2000; ++j)
    {
        ctx->b[ctx->c++]
            = (!((7 - (j & 7)) >> 1) * ((j >> 3) >> (((~(j & 7)) & 1) << 3)))
            & 0xFF;
    }

    while (j < 0x2000)
    {
        B2B_H(ctx, aux);

        for ( ; ctx->c < 128 && j < 0x2000; ++j)
        {
            ctx->b[ctx->c++]
                = (
                    !((7 - (j & 7)) >> 1)
                    * ((j >> 3) >> (((~(j & 7)) & 1) << 3))
                ) & 0xFF;
        }
    }

    //====================================================================//
    //  Hash public key, message & one-time public key
    //====================================================================//
    for (j = 0; ctx->c < 128 && j < 2 * PK_SIZE_8 + NUM_SIZE_8; ++j)
    {
        ctx->b[ctx->c++] = ((const uint8_t *)rem)[j];
    }

    while (j < 2 * PK_SIZE_8 + NUM_SIZE_8)
    {
        B2B_H(ctx, aux);
       
        while (ctx->c < 128 && j < 2 * PK_SIZE_8 + NUM_SIZE_8)
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
        ((uint8_t *)ldata)[NUM_SIZE_8 - j - 1]
            = (ctx->h[j >> 3] >> ((j & 7) << 3)) & 0xFF;
    }

    //===================================================================//
    //  Dump result to global memory -- BIG ENDIAN
    //===================================================================//
    j = ((uint64_t *)ldata)[3] < FQ3
        || ((uint64_t *)ldata)[3] == FQ3 && (
            ((uint64_t *)ldata)[2] < FQ2
            || ((uint64_t *)ldata)[2] == FQ2 && (
                ((uint64_t *)ldata)[1] < FQ1
                || ((uint64_t *)ldata)[1] == FQ1
                && ((uint64_t *)ldata)[0] < FQ0
            )
        );

    invalid[tid] = (1 - j) * (tid + 1);

#pragma unroll
    for (int i = 0; i < NUM_SIZE_8; ++i)
    {
        ((uint8_t *)hash)[tid * NUM_SIZE_8 + NUM_SIZE_8 - i - 1]
            = ((uint8_t *)ldata)[i];
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Unfinalized first iteration of hashes precalculation
////////////////////////////////////////////////////////////////////////////////
/// inoperable /// __global__ void unfinalInitPrehash(
/// inoperable ///     // data: pk
/// inoperable ///     const uint32_t * data,
/// inoperable ///     // unfinalized hash contexts
/// inoperable ///     blake2b_ctx * uctx
/// inoperable /// ) {
/// inoperable ///     uint32_t j;
/// inoperable ///     uint32_t tid = threadIdx.x;
/// inoperable /// 
/// inoperable ///     // shared memory
/// inoperable ///     __shared__ uint32_t sdata[B_DIM];
/// inoperable /// 
/// inoperable ///     sdata[tid] = data[tid];
/// inoperable ///     __syncthreads();
/// inoperable /// 
/// inoperable ///     // pk
/// inoperable ///     // PK_SIZE_8 bytes
/// inoperable ///     uint32_t * pk = sdata;
/// inoperable /// 
/// inoperable ///     // local memory
/// inoperable ///     // 472 bytes
/// inoperable ///     uint32_t ldata[118];
/// inoperable /// 
/// inoperable ///     // 32 * 64 bits = 256 bytes 
/// inoperable ///     uint64_t * aux = (uint64_t *)ldata;
/// inoperable ///     // (212 + 4) bytes 
/// inoperable ///     blake2b_ctx * ctx = (blake2b_ctx *)(ldata + 64);
/// inoperable /// 
/// inoperable ///     tid += blockDim.x * blockIdx.x;
/// inoperable /// 
/// inoperable ///     //====================================================================//
/// inoperable ///     //  Initialize context
/// inoperable ///     //====================================================================//
/// inoperable ///     B2B_IV(ctx->h);
/// inoperable /// 
/// inoperable ///     ctx->h[0] ^= 0x01010000 ^ (0 << 8) ^ NUM_SIZE_8;
/// inoperable ///     ctx->t[0] = 0;
/// inoperable ///     ctx->t[1] = 0;
/// inoperable ///     ctx->c = 0;
/// inoperable /// 
/// inoperable /// #pragma unroll
/// inoperable ///     for (j = 0; j < 128; ++j)
/// inoperable ///     {
/// inoperable ///         ctx->b[j] = 0;
/// inoperable ///     }
/// inoperable /// 
/// inoperable ///     //====================================================================//
/// inoperable ///     //  Hash tid
/// inoperable ///     //====================================================================//
/// inoperable /// #pragma unroll
/// inoperable ///     for (j = 0; ctx->c < 128 && j < 4; ++j)
/// inoperable ///     {
/// inoperable ///         ctx->b[ctx->c++] = ((const uint8_t *)&tid)[j];
/// inoperable ///     }
/// inoperable /// 
/// inoperable /// /// never reached /// #pragma unroll
/// inoperable /// /// never reached ///     for ( ; j < 4; )
/// inoperable /// /// never reached ///     {
/// inoperable /// /// never reached ///         B2B_H(ctx, aux);
/// inoperable /// /// never reached ///        
/// inoperable /// /// never reached /// #pragma unroll
/// inoperable /// /// never reached ///         for ( ; ctx->c < 128 && j < 4; ++j)
/// inoperable /// /// never reached ///         {
/// inoperable /// /// never reached ///             ctx->b[ctx->c++] = ((const uint8_t *)tid)[j];
/// inoperable /// /// never reached ///         }
/// inoperable /// /// never reached ///     }
/// inoperable /// 
/// inoperable ///     //====================================================================//
/// inoperable ///     //  Hash constant message
/// inoperable ///     //====================================================================//
/// inoperable ///     for (j = 0; ctx->c < 128 && j < 0x1000; ++j)
/// inoperable ///     {
/// inoperable ///         ctx->b[ctx->c++] = !(j & 3) * (j >> 2);
/// inoperable ///     }
/// inoperable /// 
/// inoperable ///     while (j < 0x1000)
/// inoperable ///     {
/// inoperable ///         B2B_H(ctx, aux);
/// inoperable ///        
/// inoperable ///         for ( ; ctx->c < 128 && j < 0x1000; ++j)
/// inoperable ///         {
/// inoperable ///             ctx->b[ctx->c++] = !(j & 3) * (j >> 2);
/// inoperable ///         }
/// inoperable ///     }
/// inoperable /// 
/// inoperable ///     //====================================================================//
/// inoperable ///     //  Hash public key
/// inoperable ///     //====================================================================//
/// inoperable /// #pragma unroll
/// inoperable ///     for (j = 0; ctx->c < 128 && j < PK_SIZE_8; ++j)
/// inoperable ///     {
/// inoperable ///         ctx->b[ctx->c++] = ((const uint8_t *)pk)[j];
/// inoperable ///     }
/// inoperable /// 
/// inoperable /// #pragma unroll
/// inoperable ///     for ( ; j < PK_SIZE_8; )
/// inoperable ///     {
/// inoperable ///         B2B_H(ctx, aux);
/// inoperable ///        
/// inoperable /// #pragma unroll
/// inoperable ///         for ( ; ctx->c < 128 && j < PK_SIZE_8; )
/// inoperable ///         {
/// inoperable ///             ctx->b[ctx->c++] = ((const uint8_t *)pk)[j++];
/// inoperable ///         }
/// inoperable ///     }
/// inoperable /// 
/// inoperable ///     //===================================================================//
/// inoperable ///     //  Dump result to global memory
/// inoperable ///     //===================================================================//
/// inoperable ///     uctx[tid] = *ctx;
/// inoperable /// 
/// inoperable ///     return;
/// inoperable /// }

////////////////////////////////////////////////////////////////////////////////
//  Rehash out of bounds hashes
////////////////////////////////////////////////////////////////////////////////
__global__ void updatePrehash(
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid,
    const uint32_t len
) {
    uint32_t tid = threadIdx.x + blockDim.x * blockIdx.x;

    if (tid < len)
    {
        uint32_t j;
        uint32_t addr = invalid[tid] - 1;

        // local memory
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
            ctx->b[ctx->c++]
                = ((const uint8_t *)(hash + addr * NUM_SIZE_32))[j];
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
            ((uint8_t *)ldata)[NUM_SIZE_8 - j - 1]
                = (ctx->h[j >> 3] >> ((j & 7) << 3)) & 0xFF;
        }

    //===================================================================//
    //  Dump result to global memory -- BIG ENDIAN
    //===================================================================//
        j = ((uint64_t *)ldata)[3] < FQ3
            || ((uint64_t *)ldata)[3] == FQ3 && (
                ((uint64_t *)ldata)[2] < FQ2
                || ((uint64_t *)ldata)[2] == FQ2 && (
                    ((uint64_t *)ldata)[1] < FQ1
                    || ((uint64_t *)ldata)[1] == FQ1
                    && ((uint64_t *)ldata)[0] < FQ0
                )
            );

        invalid[tid] *= 1 - j;

#pragma unroll
        for (int i = 0; i < NUM_SIZE_8; ++i)
        {
            ((uint8_t *)hash)[addr * NUM_SIZE_8 + NUM_SIZE_8 - i - 1]
                = ((uint8_t *)ldata)[i];
        }
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Hashes modulo Q
////////////////////////////////////////////////////////////////////////////////
__global__ void finalPrehash(
    // hashes
    uint32_t * hash
) {
    uint32_t tid = threadIdx.x + blockDim.x * blockIdx.x;

    // local memory
    uint32_t h[10];

#pragma unroll
    for (int i = 0; i < NUM_SIZE_8; ++i)
    {
         ((uint8_t *)h)[i]
             = ((uint8_t *)hash)[tid * NUM_SIZE_8 + NUM_SIZE_8 - i - 1]; 
    }

    h[9] = h[8] = 0;

    //====================================================================//
    //  mod Q
    //====================================================================//
    uint32_t d[2]; 
    uint32_t med[6];
    uint32_t carry;

#pragma unroll
    for (int i = 10; i >= 8; i -= 2)
    {
        *((uint64_t *)d) = (
                (((uint64_t *)h)[i >> 1] << 4)
                | (((uint64_t *)h)[(i >> 1) - 1] >> 60)
            ) - (((uint64_t *)h)[i >> 1] >> 60);

        // correct highest 32 bits
        h[i - 1] = (h[i - 1] & 0x0FFFFFFF) | h[i + 1] & 0x10000000;

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
    //  r[i/2 - 2, i/2 - 3, i/2 - 4] mod Q
    //====================================================================//
        asm volatile (
            "sub.cc.u32 %0, %0, %1;": "+r"(h[i - 8]): "r"(med[0])
        );

#pragma unroll
        for (int j = 1; j < 6; ++j)
        {
            asm volatile (
                "subc.cc.u32 %0, %0, %1;": "+r"(h[i + j - 8]): "r"(med[j])
            );
        }

        asm volatile (
            "subc.cc.u32 %0, %0, 0;": "+r"(h[i - 2])
        );

        asm volatile (
            "subc.cc.u32 %0, %0, 0;": "+r"(h[i - 1])
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
            "mad.lo.cc.u32 %0, %1, "q0_s", %0;": "+r"(h[i - 8]): "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q1_s", %0;": "+r"(h[i - 7]): "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q2_s", %0;": "+r"(h[i - 6]): "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;": "+r"(h[i - 5]): "r"(carry)
        );

    //====================================================================//
#pragma unroll
        for (int j = 0; j < 3; ++j)
        {
            asm volatile (
                "addc.cc.u32 %0, %0, 0;": "+r"(h[i + j - 4])
            );
        }

        asm volatile (
            "addc.u32 %0, %0, 0;": "+r"(h[i - 1])
        );
    }

    //===================================================================//
    //  Dump result to global memory -- BIG ENDIAN
    //===================================================================//
#pragma unroll
    for (int i = 0; i < NUM_SIZE_8; ++i)
    {
        ((uint8_t *)hash)[tid * NUM_SIZE_8 + i]
            = ((uint8_t *)h)[NUM_SIZE_8 - i - 1];
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Hashes multiplication modulo Q by one time secret key 
////////////////////////////////////////////////////////////////////////////////
__global__ void finalPrehashMultSK(
    // data: pk || mes || w || padding || x || sk
    const uint32_t * data,
    // hashes
    uint32_t * hash
) {
    uint32_t tid = threadIdx.x;

    // shared memory
    __shared__ uint32_t sdata[B_DIM];

    sdata[tid] = data[tid + PK2_SIZE_32 + NUM_SIZE_32];
    __syncthreads();

    tid += blockDim.x * blockIdx.x;

    // x
    // NUM_SIZE_8 bytes
    uint32_t * x = sdata;

    // local memory
    uint32_t h[NUM_SIZE_32];

#pragma unroll
    for (int i = 0; i < NUM_SIZE_8; ++i)
    {
         ((uint8_t *)h)[i]
             = ((uint8_t *)hash)[tid * NUM_SIZE_8 + NUM_SIZE_8 - i - 1]; 
    }

    uint32_t r[18];
    r[16] = r[17] = 0;

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
    //  mod Q
    //====================================================================//
    uint32_t d[2]; 
    uint32_t med[6];
    uint32_t carry;

#pragma unroll
    for (int i = 16; i >= 8; i -= 2)
    {
        *((uint64_t *)d) = (
                (((uint64_t *)r)[i >> 1] << 4)
                | (((uint64_t *)r)[(i >> 1) - 1] >> 60)
            ) - (((uint64_t *)r)[i >> 1] >> 60);

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
    //  r[i/2 - 2, i/2 - 3, i/2 - 4] mod Q
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
    //  Dump result to global memory -- LITTLE ENDIAN
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
    // data: pk || mes || w || padding || x || sk
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid
) {
    uint32_t len = N_LEN; // >= H_LEN * N_LEN -- critical assumption

    uint32_t * ind = invalid;
    uint32_t * comp = invalid + N_LEN;
    uint32_t * tmp;

    /// debug /// uint32_t * indices_h = (uint32_t *)malloc(len * 4);

    // put zero to new length 
    CUDA_CALL(cudaMemset((void *)(invalid + 2 * N_LEN), 0, 4));

    // hash index, constant message and public key
    initPrehash<<<1 + (N_LEN - 1) / B_DIM, B_DIM>>>(data, hash, ind);

    /// debug /// //from//
    /// debug /// CUDA_CALL(cudaMemcpy(
    /// debug ///     (void *)indices_h, (void *)ind, len * 4,
    /// debug ///     cudaMemcpyDeviceToHost
    /// debug /// ));
    /// debug /// for (int i = 0; i < len && i < 750; ++i)
    /// debug /// {
    /// debug ///     // if (i == 1 || i == 741)
    /// debug ///         printf("%"PRIx32" ", indices_h[i]);
    /// debug /// }
    /// debug /// printf("\n\n");
    /// debug /// fflush(stdout);
    /// debug /// //to//

    // determine indices of out of bounds hashes
    compactify<<<1 + (N_LEN - 1) / B_DIM, B_DIM>>>(
        ind, len, comp, invalid + 2 * N_LEN
    );

    // determine the quantity of invalid hashes
    CUDA_CALL(cudaMemcpy(
        (void *)&len, (void *)(invalid + 2 * N_LEN), 4, cudaMemcpyDeviceToHost
    ));

    tmp = ind;
    ind = comp;
    comp = tmp;

    /// debug /// //from//
    /// debug /// CUDA_CALL(cudaMemcpy(
    /// debug ///     (void *)indices_h, (void *)ind, len * 4,
    /// debug ///     cudaMemcpyDeviceToHost
    /// debug /// ));
    /// debug /// for (int i = 0; i < len && i < 750; ++i)
    /// debug /// {
    /// debug ///     // if (i == 1 || i == 741)
    /// debug ///         printf("%"PRIx32" ", indices_h[i]);
    /// debug /// }
    /// debug /// printf("\n\n");
    /// debug /// fflush(stdout);
    /// debug /// //to//

    while (len)
    {
        // put zero to new length 
        CUDA_CALL(cudaMemset((void *)(invalid + 2 * N_LEN), 0, 4));

        // rehash out of bounds hashes
        updatePrehash<<<1 + (len - 1) / B_DIM, B_DIM>>>(hash, ind, len);

        // determine indices of out of bounds hashes
        compactify<<<1 + (len - 1) / B_DIM, B_DIM>>>(
            ind, len, comp, invalid + 2 * N_LEN
        );

        // determine the quantity of invalid hashes
        CUDA_CALL(cudaMemcpy(
            (void *)&len, (void *)(invalid + 2 * N_LEN), 4,
            cudaMemcpyDeviceToHost
        ));

        tmp = ind;
        ind = comp;
        comp = tmp;
    }

    // multiply by secret key moq Q
    finalPrehashMultSK<<<1 + (N_LEN - 1) / B_DIM, B_DIM>>>(data, hash);

    /// debug /// free(indices_h);
    return 0;
}

// prehash.cu
