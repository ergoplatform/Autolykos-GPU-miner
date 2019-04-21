// prehash.cu

/*******************************************************************************

    PREHASH -- precalculation of hashes

*******************************************************************************/

#include "../include/prehash.h"
#include "../include/compaction.h"
#include "../include/definitions.h"
#include <cuda.h>

////////////////////////////////////////////////////////////////////////////////
//  First iteration of hashes precalculation
////////////////////////////////////////////////////////////////////////////////
__global__ void InitPrehash(
    // data: pk || mes || w || padding || x || sk
    const uint32_t * data,
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid
)
{
    uint32_t j;
    uint32_t tid = threadIdx.x;

    // shared memory
    __shared__ uint32_t sdata[BLOCK_DIM];

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
    context_t * ctx = (context_t *)(ldata + 64);

    tid += blockDim.x * blockIdx.x;

    //====================================================================//
    //  Initialize context
    //====================================================================//
    memset(ctx->b, 0, BUF_SIZE_8);
    B2B_IV(ctx->h);
    ctx->h[0] ^= 0x01010000 ^ NUM_SIZE_8;
    memset(ctx->t, 0, 16);
    ctx->c = 0;

    //====================================================================//
    //  Hash tid
    //====================================================================//
#pragma unroll
    for (j = 0; ctx->c < BUF_SIZE_8 && j < INDEX_SIZE_8; ++j)
    {
        ctx->b[ctx->c++] = ((const uint8_t *)&tid)[INDEX_SIZE_8 - j - 1];
    }

    //====================================================================//
    //  Hash constant message
    //====================================================================//
#pragma unroll
    for (j = 0; ctx->c < BUF_SIZE_8 && j < CONST_MES_SIZE_8; ++j)
    {
        ctx->b[ctx->c++]
            = (!((7 - (j & 7)) >> 1) * ((j >> 3) >> (((~(j & 7)) & 1) << 3)))
            & 0xFF;
    }

    while (j < CONST_MES_SIZE_8)
    {
        DEVICE_B2B_H(ctx, aux);

        for ( ; ctx->c < BUF_SIZE_8 && j < CONST_MES_SIZE_8; ++j)
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
#pragma unroll
    for (j = 0; ctx->c < BUF_SIZE_8 && j < 2 * PK_SIZE_8 + NUM_SIZE_8; ++j)
    {
        ctx->b[ctx->c++] = ((const uint8_t *)rem)[j];
    }

    while (j < 2 * PK_SIZE_8 + NUM_SIZE_8)
    {
        DEVICE_B2B_H(ctx, aux);
       
        while (ctx->c < BUF_SIZE_8 && j < 2 * PK_SIZE_8 + NUM_SIZE_8)
        {
            ctx->b[ctx->c++] = ((const uint8_t *)rem)[j++];
        }
    }

    //====================================================================//
    //  Finalize hash
    //====================================================================//
    DEVICE_B2B_H_LAST(ctx, aux);

#pragma unroll
    for (j = 0; j < NUM_SIZE_8; ++j)
    {
        ((uint8_t *)ldata)[NUM_SIZE_8 - j - 1]
            = (ctx->h[j >> 3] >> ((j & 7) << 3)) & 0xFF;
    }

    //===================================================================//
    //  Dump result to global memory -- BIG ENDIAN
    //===================================================================//
    j = ((uint64_t *)ldata)[3] < Q3
        || ((uint64_t *)ldata)[3] == Q3 && (
            ((uint64_t *)ldata)[2] < Q2
            || ((uint64_t *)ldata)[2] == Q2 && (
                ((uint64_t *)ldata)[1] < Q1
                || ((uint64_t *)ldata)[1] == Q1
                && ((uint64_t *)ldata)[0] < Q0
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
//  Uncompleted first iteration of hashes precalculation
////////////////////////////////////////////////////////////////////////////////
__global__ void UncompleteInitPrehash(
    // data: pk
    const uint32_t * data,
    // unfinalized hash contexts
    ucontext_type * uctxs
)
{
    uint32_t j;
    uint32_t tid = threadIdx.x;

    // shared memory
    __shared__ uint32_t sdata[BLOCK_DIM];

    sdata[tid] = data[tid];
    __syncthreads();

    // public key
    // PK_SIZE_8 bytes
    uint32_t * pk = sdata;

    // local memory
    // 472 bytes
    uint32_t ldata[118];

    // 32 * 64 bits = 256 bytes 
    uint64_t * aux = (uint64_t *)ldata;
    // (212 + 4) bytes 
    context_t * ctx = (context_t *)(ldata + 64);

    tid += blockDim.x * blockIdx.x;

    //====================================================================//
    //  Initialize context
    //====================================================================//
    memset(ctx->b, 0, BUF_SIZE_8);
    B2B_IV(ctx->h);
    ctx->h[0] ^= 0x01010000 ^ NUM_SIZE_8;
    memset(ctx->t, 0, 16);
    ctx->c = 0;

    //====================================================================//
    //  Hash tid
    //====================================================================//
#pragma unroll
    for (j = 0; ctx->c < BUF_SIZE_8 && j < INDEX_SIZE_8; ++j)
    {
        ctx->b[ctx->c++] = ((const uint8_t *)&tid)[INDEX_SIZE_8 - j - 1];
    }

    //====================================================================//
    //  Hash constant message
    //====================================================================//
#pragma unroll
    for (j = 0; ctx->c < BUF_SIZE_8 && j < CONST_MES_SIZE_8; ++j)
    {
        ctx->b[ctx->c++]
            = (!((7 - (j & 7)) >> 1) * ((j >> 3) >> (((~(j & 7)) & 1) << 3)))
            & 0xFF;
    }

    while (j < CONST_MES_SIZE_8)
    {
        DEVICE_B2B_H(ctx, aux);

        for ( ; ctx->c < BUF_SIZE_8 && j < CONST_MES_SIZE_8; ++j)
        {
            ctx->b[ctx->c++]
                = (
                    !((7 - (j & 7)) >> 1)
                    * ((j >> 3) >> (((~(j & 7)) & 1) << 3))
                ) & 0xFF;
        }
    }

    //====================================================================//
    //  Hash public key
    //====================================================================//
#pragma unroll
    for (j = 0; ctx->c < BUF_SIZE_8 && j < PK_SIZE_8; ++j)
    {
        ctx->b[ctx->c++] = ((const uint8_t *)pk)[j];
    }

#pragma unroll
    for ( ; j < PK_SIZE_8; )
    {
        DEVICE_B2B_H(ctx, aux);
       
#pragma unroll
        for ( ; ctx->c < BUF_SIZE_8 && j < PK_SIZE_8; )
        {
            ctx->b[ctx->c++] = ((const uint8_t *)pk)[j++];
        }
    }

    //===================================================================//
    //  Dump result to global memory
    //===================================================================//
    memcpy(uctxs[tid].h, ctx->h, 8 * sizeof(uint64_t));
    memcpy(uctxs[tid].t, ctx->t, 2 * sizeof(uint64_t));

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Completed first iteration of hashes precalculation
////////////////////////////////////////////////////////////////////////////////
__global__ void CompleteInitPrehash(
    // data: pk || mes || w || padding || x || sk
    const uint32_t * data,
    // unfinalized hash contexts
    const ucontext_type * uctxs,
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid
)
{
    uint32_t j;
    uint32_t tid = threadIdx.x;

    // shared memory
    __shared__ uint32_t sdata[BLOCK_DIM];

    sdata[tid] = data[tid];
    __syncthreads();

    // mes || w
    // PK_SIZE_8 + NUM_SIZE_8 bytes
    uint8_t * rem = (uint8_t *)sdata + PK_SIZE_8;

    // local memory
    // 472 bytes
    uint32_t ldata[118];

    // 32 * 64 bits = 256 bytes 
    uint64_t * aux = (uint64_t *)ldata;
    // (212 + 4) bytes 
    context_t * ctx = (context_t *)(ldata + 64);

    tid += blockDim.x * blockIdx.x;

    //====================================================================//
    //  Initialize context
    //====================================================================//
    ctx->c = CONTINUE_POS;

#pragma unroll
    for (
        j = CONST_MES_SIZE_8 - 129 + PK_SIZE_8;
        ctx->c < BUF_SIZE_8 && j < CONST_MES_SIZE_8;
        ++j
    )
    {
        ctx->b[ctx->c++]
            = (!((7 - (j & 7)) >> 1) * ((j >> 3) >> (((~(j & 7)) & 1) << 3)))
            & 0xFF;
    }

    ctx->c = 0;

#pragma unroll
    for ( ; j < CONST_MES_SIZE_8; ++j)
    {
        ctx->b[ctx->c++]
            = (!((7 - (j & 7)) >> 1) * ((j >> 3) >> (((~(j & 7)) & 1) << 3)))
            & 0xFF;
    }

    memcpy(ctx->b + ctx->c, (uint8_t *)data, PK_SIZE_8); 
    ctx->c += PK_SIZE_8;

    memcpy(ctx->h, uctxs[tid].h, 8 * sizeof(uint64_t));
    memcpy(ctx->t, uctxs[tid].t, 2 * sizeof(uint64_t));

    //====================================================================//
    //  Hash public key, message & one-time public key
    //====================================================================//
#pragma unroll
    for (j = 0; ctx->c < BUF_SIZE_8 && j < PK_SIZE_8 + NUM_SIZE_8; ++j)
    {
        ctx->b[ctx->c++] = rem[j];
    }

    while (j < PK_SIZE_8 + NUM_SIZE_8)
    {
        DEVICE_B2B_H(ctx, aux);
       
        while (ctx->c < BUF_SIZE_8 && j < PK_SIZE_8 + NUM_SIZE_8)
        {
            ctx->b[ctx->c++] = rem[j++];
        }
    }

    //====================================================================//
    //  Finalize hash
    //====================================================================//
    DEVICE_B2B_H_LAST(ctx, aux);

#pragma unroll
    for (j = 0; j < NUM_SIZE_8; ++j)
    {
        ((uint8_t *)ldata)[NUM_SIZE_8 - j - 1]
            = (ctx->h[j >> 3] >> ((j & 7) << 3)) & 0xFF;
    }

    //===================================================================//
    //  Dump result to global memory -- BIG ENDIAN
    //===================================================================//
    j = ((uint64_t *)ldata)[3] < Q3
        || ((uint64_t *)ldata)[3] == Q3 && (
            ((uint64_t *)ldata)[2] < Q2
            || ((uint64_t *)ldata)[2] == Q2 && (
                ((uint64_t *)ldata)[1] < Q1
                || ((uint64_t *)ldata)[1] == Q1
                && ((uint64_t *)ldata)[0] < Q0
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
//  Rehash out of bounds hashes
////////////////////////////////////////////////////////////////////////////////
__global__ void UpdatePrehash(
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid,
    const uint32_t len
)
{
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
        context_t * ctx = (context_t *)(ldata + 64);

    //====================================================================//
    //  Initialize context
    //====================================================================//
        memset(ctx->b, 0, BUF_SIZE_8);
        B2B_IV(ctx->h);
        ctx->h[0] ^= 0x01010000 ^ NUM_SIZE_8;
        memset(ctx->t, 0, 16);
        ctx->c = 0;

    //====================================================================//
    //  Hash previous hash
    //====================================================================//
#pragma unroll
        for (j = 0; ctx->c < BUF_SIZE_8 && j < NUM_SIZE_8; ++j)
        {
            ctx->b[ctx->c++]
                = ((const uint8_t *)(hash + addr * NUM_SIZE_32))[j];
        }

#pragma unroll
        for ( ; j < NUM_SIZE_8; )
        {
            DEVICE_B2B_H(ctx, aux);
           
#pragma unroll
            for ( ; ctx->c < BUF_SIZE_8 && j < NUM_SIZE_8; ++j)
            {
                ctx->b[ctx->c++]
                    = ((const uint8_t *)(hash + addr * NUM_SIZE_32))[j];
            }
        }

    //====================================================================//
    //  Finalize hash
    //====================================================================//
        DEVICE_B2B_H_LAST(ctx, aux);

#pragma unroll
        for (j = 0; j < NUM_SIZE_8; ++j)
        {
            ((uint8_t *)ldata)[NUM_SIZE_8 - j - 1]
                = (ctx->h[j >> 3] >> ((j & 7) << 3)) & 0xFF;
        }

    //===================================================================//
    //  Dump result to global memory -- BIG ENDIAN
    //===================================================================//
        j = ((uint64_t *)ldata)[3] < Q3
            || ((uint64_t *)ldata)[3] == Q3 && (
                ((uint64_t *)ldata)[2] < Q2
                || ((uint64_t *)ldata)[2] == Q2 && (
                    ((uint64_t *)ldata)[1] < Q1
                    || ((uint64_t *)ldata)[1] == Q1
                    && ((uint64_t *)ldata)[0] < Q0
                )
            );

        invalid[tid] *= 1 - j;

#pragma unroll
        for (int i = 0; i < NUM_SIZE_8; ++i)
        {
            ((uint8_t *)hash)[(addr + 1) * NUM_SIZE_8 - i - 1]
                = ((uint8_t *)ldata)[i];
        }
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Hashes modulo Q
////////////////////////////////////////////////////////////////////////////////
__global__ void FinalPrehash(
    // hashes
    uint32_t * hash
)
{
    uint32_t tid = threadIdx.x + blockDim.x * blockIdx.x;

    // local memory
    uint32_t h[NUM_SIZE_32];

#pragma unroll
    for (int i = 0; i < NUM_SIZE_8; ++i)
    {
         ((uint8_t *)h)[i]
             = ((uint8_t *)hash)[tid * NUM_SIZE_8 + NUM_SIZE_8 - i - 1]; 
    }

    //====================================================================//
    //  Mod Q
    //====================================================================//
    uint32_t carry;

    asm volatile ("sub.cc.u32 %0, %0, " q0_s ";": "+r"(h[0]));
    asm volatile ("subc.cc.u32 %0, %0, " q1_s ";": "+r"(h[1]));
    asm volatile ("subc.cc.u32 %0, %0, " q2_s ";": "+r"(h[2]));
    asm volatile ("subc.cc.u32 %0, %0, " q3_s ";": "+r"(h[3]));
    asm volatile ("subc.cc.u32 %0, %0, " q4_s ";": "+r"(h[4]));

#pragma unroll
    for (int j = 5; j < 8; ++j)
    {
        asm volatile ("subc.cc.u32 %0, %0, " qhi_s ";": "+r"(h[j]));
    }

    asm volatile ("subc.u32 %0, 0, 0;": "=r"(carry));

    carry = 0 - carry;

    //====================================================================//
    asm volatile (
        "mad.lo.cc.u32 %0, %1, " q0_s ", %0;": "+r"(h[0]): "r"(carry)
    );
    asm volatile (
        "madc.lo.cc.u32 %0, %1, " q1_s ", %0;": "+r"(h[1]): "r"(carry)
    );
    asm volatile (
        "madc.lo.cc.u32 %0, %1, " q2_s ", %0;": "+r"(h[2]): "r"(carry)
    );
    asm volatile (
        "madc.lo.cc.u32 %0, %1, " q3_s ", %0;": "+r"(h[3]): "r"(carry)
    );
    asm volatile (
        "madc.lo.cc.u32 %0, %1, " q4_s ", %0;": "+r"(h[4]): "r"(carry)
    );

#pragma unroll
    for (int j = 5; j < 7; ++j)
    {
        asm volatile (
            "madc.lo.cc.u32 %0, %1, " qhi_s ", %0;": "+r"(h[j]): "r"(carry)
        );
    }

    asm volatile ("madc.lo.u32 %0, %1, " qhi_s ", %0;": "+r"(h[7]): "r"(carry));

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
__global__ void FinalPrehashMultSecKey(
    // data: pk || mes || w || padding || x || sk
    const uint32_t * data,
    // hashes
    uint32_t * hash
)
{
    uint32_t tid = threadIdx.x;

    // shared memory
    __shared__ uint32_t sdata[BLOCK_DIM];

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
         ((uint8_t *)h)[i] = ((uint8_t *)hash)[(tid + 1) * NUM_SIZE_8 - i - 1]; 
    }

    uint32_t r[NUM_SIZE_32 << 1];

    //====================================================================//
    //  r[0, ..., 7, 8] = h[0] * x
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
    //  r[i, ..., i + 7, i + 8] += h[i] * x
    //====================================================================//
#pragma unroll
    for (int i = 1; i < NUM_SIZE_32; ++i)
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
        asm volatile ("addc.u32 %0, 0, 0;": "=r"(r[i + 8]));

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
    //  Mod Q
    //====================================================================//
    uint32_t d[2]; 
    uint32_t med[6];
    uint32_t carry;

#pragma unroll
    for (int i = (NUM_SIZE_32 - 1) << 1; i >= NUM_SIZE_32; i -= 2)
    {
        *((uint64_t *)d) = ((uint64_t *)r)[i >> 1];

    //====================================================================//
    //  med[0, ..., 5] = d * Q
    //====================================================================//
        asm volatile ("mul.lo.u32 %0, %1, " q0_s ";": "=r"(med[0]): "r"(d[0]));
        asm volatile ("mul.hi.u32 %0, %1, " q0_s ";": "=r"(med[1]): "r"(d[0]));
        asm volatile ("mul.lo.u32 %0, %1, " q2_s ";": "=r"(med[2]): "r"(d[0]));
        asm volatile ("mul.hi.u32 %0, %1, " q2_s ";": "=r"(med[3]): "r"(d[0]));

        asm volatile (
            "mad.lo.cc.u32 %0, %1, " q1_s ", %0;": "+r"(med[1]): "r"(d[0])
        );

        asm volatile (
            "madc.hi.cc.u32 %0, %1, " q1_s ", %0;": "+r"(med[2]): "r"(d[0])
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, " q3_s ", %0;": "+r"(med[3]): "r"(d[0])
        );

        asm volatile (
            "madc.hi.u32 %0, %1, " q3_s ", 0;": "=r"(med[4]): "r"(d[0])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, " q0_s ", %0;": "+r"(med[1]): "r"(d[1])
        );

        asm volatile (
            "madc.hi.cc.u32 %0, %1, " q0_s ", %0;": "+r"(med[2]): "r"(d[1])
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, " q2_s ", %0;": "+r"(med[3]): "r"(d[1])
        );

        asm volatile (
            "madc.hi.cc.u32 %0, %1," q2_s", %0;": "+r"(med[4]): "r"(d[1])
        );

        asm volatile ("addc.u32 %0, 0, 0;": "=r"(med[5]));

        asm volatile (
            "mad.lo.cc.u32 %0, %1, " q1_s ", %0;": "+r"(med[2]): "r"(d[1])
        );

        asm volatile (
            "madc.hi.cc.u32 %0, %1, " q1_s ", %0;": "+r"(med[3]): "r"(d[1])
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, " q3_s ", %0;": "+r"(med[4]): "r"(d[1])
        );

        asm volatile (
            "madc.hi.u32 %0, %1, " q3_s ", %0;": "+r"(med[5]): "r"(d[1])
        );

    //====================================================================//
    //  x[i/2 - 2, i/2 - 3, i/2 - 4] -= d * Q
    //====================================================================//
        asm volatile ("sub.cc.u32 %0, %0, %1;": "+r"(r[i - 8]): "r"(med[0]));

#pragma unroll
        for (int j = 1; j < 6; ++j)
        {
            asm volatile (
                "subc.cc.u32 %0, %0, %1;": "+r"(r[i + j - 8]): "r"(med[j])
            );
        }

        asm volatile ("subc.cc.u32 %0, %0, 0;": "+r"(r[i - 2]));
        asm volatile ("subc.u32 %0, %0, 0;": "+r"(r[i - 1]));

    //====================================================================//
    //  x[i/2 - 1, i/2 - 2] += 2 * d
    //====================================================================//
        carry = d[1] >> 31;
        d[1] = (d[1] << 1) | (d[0] >> 31);
        d[0] <<= 1;

        asm volatile ("add.cc.u32 %0, %0, %1;": "+r"(r[i - 4]): "r"(d[0]));
        asm volatile ("addc.cc.u32 %0, %0, %1;": "+r"(r[i - 3]): "r"(d[1]));
        asm volatile ("addc.cc.u32 %0, %0, %1;": "+r"(r[i - 2]): "r"(carry));
        asm volatile ("addc.u32 %0, %0, 0;": "+r"(r[i - 1]));
    }

    //====================================================================//
    //  Last 256 bit correction
    //====================================================================//
    asm volatile ("sub.cc.u32 %0, %0, " q0_s ";": "+r"(r[0]));
    asm volatile ("subc.cc.u32 %0, %0, " q1_s ";": "+r"(r[1]));
    asm volatile ("subc.cc.u32 %0, %0, " q2_s ";": "+r"(r[2]));
    asm volatile ("subc.cc.u32 %0, %0, " q3_s ";": "+r"(r[3]));
    asm volatile ("subc.cc.u32 %0, %0, " q4_s ";": "+r"(r[4]));

#pragma unroll
    for (int j = 5; j < 8; ++j)
    {
        asm volatile ("subc.cc.u32 %0, %0, " qhi_s ";": "+r"(r[j]));
    }

    //====================================================================//
    asm volatile ("subc.u32 %0, 0, 0;": "=r"(carry));

    carry = 0 - carry;

    //====================================================================//
    asm volatile (
        "mad.lo.cc.u32 %0, %1, " q0_s ", %0;": "+r"(r[0]): "r"(carry)
    );
    asm volatile (
        "madc.lo.cc.u32 %0, %1, " q1_s ", %0;": "+r"(r[1]): "r"(carry)
    );
    asm volatile (
        "madc.lo.cc.u32 %0, %1, " q2_s ", %0;": "+r"(r[2]): "r"(carry)
    );
    asm volatile (
        "madc.lo.cc.u32 %0, %1, " q3_s ", %0;": "+r"(r[3]): "r"(carry)
    );
    asm volatile (
        "madc.lo.cc.u32 %0, %1, " q4_s ", %0;": "+r"(r[4]): "r"(carry)
    );

#pragma unroll
    for (int j = 5; j < 7; ++j)
    {
        asm volatile (
            "madc.lo.cc.u32 %0, %1, " qhi_s ", %0;": "+r"(r[j]): "r"(carry)
        );
    }

    asm volatile ("madc.lo.u32 %0, %1, " qhi_s ", %0;": "+r"(r[7]): "r"(carry));

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
int Prehash(
    const int keep,
    // data: pk || mes || w || padding || x || sk
    const uint32_t * data,
    // unfinalized hash contexts
    ucontext_type * uctxs,
    // hashes
    uint32_t * hash,
    // indices of invalid range hashes
    uint32_t * invalid
)
{
    uint32_t len = N_LEN; // N_LEN >= THREAD_LEN * LOAD_LEN -- assumption

    uint32_t * ind = invalid;
    uint32_t * comp = invalid + N_LEN;
    uint32_t * tmp;

    // put zero to new length 
    CUDA_CALL(cudaMemset((void *)(invalid + 2 * N_LEN), 0, INDEX_SIZE_8));

    // complete init prehash by hashing message and public key
    if (keep)
    {
        CompleteInitPrehash<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            data, uctxs, hash, ind
        );
    }
    // hash index, constant message and public key
    else
    {
        InitPrehash<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            data, hash, ind
        );
    }

    // determine indices of out of bounds hashes
    Compactify<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
        ind, len, comp, invalid + 2 * N_LEN
    );

    // determine the quantity of invalid hashes
    CUDA_CALL(cudaMemcpy(
        (void *)&len, (void *)(invalid + 2 * N_LEN), INDEX_SIZE_8,
        cudaMemcpyDeviceToHost
    ));

    tmp = ind;
    ind = comp;
    comp = tmp;

    while (len)
    {
        // put zero to new length 
        CUDA_CALL(cudaMemset((void *)(invalid + 2 * N_LEN), 0, INDEX_SIZE_8));

        // rehash out of bounds hashes
        UpdatePrehash<<<1 + (len - 1) / BLOCK_DIM, BLOCK_DIM>>>(hash, ind, len);

        // determine indices of out of bounds hashes
        Compactify<<<1 + (len - 1) / BLOCK_DIM, BLOCK_DIM>>>(
            ind, len, comp, invalid + 2 * N_LEN
        );

        // determine the quantity of invalid hashes
        CUDA_CALL(cudaMemcpy(
            (void *)&len, (void *)(invalid + 2 * N_LEN), INDEX_SIZE_8,
            cudaMemcpyDeviceToHost
        ));

        tmp = ind;
        ind = comp;
        comp = tmp;
    }

    // multiply by secret key moq Q
    FinalPrehashMultSecKey<<<1 + (N_LEN - 1) / BLOCK_DIM, BLOCK_DIM>>>(
        data, hash
    );

    return EXIT_SUCCESS;
}

// prehash.cu
