// mining.cu

/*******************************************************************************

    MINING -- Autolykos parallel BlockMining procedure

*******************************************************************************/

#include "../include/mining.h"
#include <cuda.h>

////////////////////////////////////////////////////////////////////////////////
//  Unfinalized hash of message
////////////////////////////////////////////////////////////////////////////////
void InitMining(
    // context
    blake2b_ctx * ctx,
    // message
    const uint32_t * mes,
    // message length in bytes
    const uint32_t meslen
)
{
    int j;

    uint64_t aux[32];

    //====================================================================//
    //  Initialize context
    //====================================================================//
    B2B_IV(ctx->h);

    ctx->h[0] ^= 0x01010000 ^ (0 << 8) ^ NUM_SIZE_8;
    ctx->t[0] = 0;
    ctx->t[1] = 0;
    ctx->c = 0;

    for (j = 0; j < 128; ++j)
    {
        ctx->b[j] = 0;
    }

    //====================================================================//
    //  Hash message
    //====================================================================//
    for (j = 0; j < meslen; ++j)
    {
        if (ctx->c == 128)
        {
            B2B_H_HOST(ctx, aux);
        }

        ctx->b[ctx->c++] = ((const uint8_t *)mes)[j];
    }

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Block mining                                                               
////////////////////////////////////////////////////////////////////////////////
__global__ void BlockMining(
    // boundary for puzzle
    const uint32_t * bound,
    // data: pk || mes || w || padding || x || sk || ctx
    const uint32_t * data,
    // pregenerated nonces
    const uint32_t * non,
    // precalculated hashes
    const uint32_t * hash,
    // results
    uint32_t * res,
    // indices of valid solutions
    uint32_t * valid
)
{
    uint32_t j;
    uint32_t tid = threadIdx.x;

    // shared memory
    // B_DIM * 4 bytes  
    __shared__ uint32_t sdata[B_DIM];

    // B_DIM * 4 bytes
    sdata[tid] = data[tid + PK2_SIZE_32 + 2 * NUM_SIZE_32];
    __syncthreads();

    // NUM_SIZE_8 bytes
    uint32_t * sk = sdata;

    // local memory
    // 472 bytes
    uint32_t ldata[118];

    // 256 bytes
    uint64_t * aux = (uint64_t *)ldata;
    // (4 * K_LEN) bytes
    uint32_t * ind = ldata;
    // (NUM_SIZE_8 + 4) bytes
    uint32_t * r = ind + K_LEN;
    // (212 + 4) bytes 
    blake2b_ctx * ctx = (blake2b_ctx *)(ldata + 64);

#pragma unroll
    for (int l = 0; l < H_LEN; ++l) 
    {
        *ctx = *((blake2b_ctx *)(sdata + NUM_SIZE_32));

        tid = threadIdx.x + blockDim.x * blockIdx.x
            + l * gridDim.x * blockDim.x;

        const uint8_t * mes = (const uint8_t *)(non + tid * NONCE_SIZE_32);

    //====================================================================//
    //  Hash nonce
    //====================================================================//
#pragma unroll
        for (j = 0; ctx->c < 128 && j < NONCE_SIZE_8; ++j)
        {
            ctx->b[ctx->c++] = mes[j];
        }

#pragma unroll
        for ( ; j < NONCE_SIZE_8; )
        {
            B2B_H(ctx, aux);
           
#pragma unroll
            for ( ; ctx->c < 128 && j < NONCE_SIZE_8; ++j)
            {
                ctx->b[ctx->c++] = mes[j];
            }
        }

    //====================================================================//
    //  Finalize hash
    //====================================================================//
        B2B_H_LAST(ctx, aux);

#pragma unroll
        for (j = 0; j < NUM_SIZE_8; ++j)
        {
            ((uint8_t *)r)[(j & 0xFFFFFFFC) + (3 - (j & 3))]
                = (ctx->h[j >> 3] >> ((j & 7) << 3)) & 0xFF;
        }

    //===================================================================//
    //  Generate indices
    //===================================================================//
#pragma unroll
        for (int i = 1; i < 4; ++i)
        {
            ((uint8_t *)r)[NUM_SIZE_8 + i] = ((uint8_t *)r)[i];
        }

#pragma unroll
        for (int k = 0; k < K_LEN; k += 4) 
        { 
            ind[k] = r[k >> 2] & N_MASK; 
        
#pragma unroll 
            for (int i = 1; i < 4; ++i) 
            { 
                ind[k + i] 
                    = (
                        (r[k >> 2] << (i << 3))
                        | (r[(k >> 2) + 1] >> (32 - (i << 3)))
                    ) & N_MASK; 
            } 
        } 

    //===================================================================//
    //  Calculate result
    //===================================================================//
        // first addition of hashes -> r
        asm volatile (
            "add.cc.u32 %0, %1, %2;":
            "=r"(r[0]): "r"(hash[ind[0] << 3]), "r"(hash[ind[1] << 3])
        );

#pragma unroll
        for (int i = 1; i < 8; ++i)
        {
            asm volatile (
                "addc.cc.u32 %0, %1, %2;":
                "=r"(r[i]):
                "r"(hash[(ind[0] << 3) + i]), "r"(hash[(ind[1] << 3) + i])
            );
        }

        asm volatile ("addc.u32 %0, 0, 0;": "=r"(r[8]));

     // remaining additions
#pragma unroll
        for (int k = 2; k < K_LEN; ++k)
        {
            asm volatile (
                "add.cc.u32 %0, %0, %1;": "+r"(r[0]): "r"(hash[ind[k] << 3])
            );

#pragma unroll
            for (int i = 1; i < 8; ++i)
            {
                asm volatile (
                    "addc.cc.u32 %0, %0, %1;":
                    "+r"(r[i]): "r"(hash[(ind[k] << 3) + i])
                );
            }

            asm volatile ("addc.u32 %0, %0, 0;": "+r"(r[8]));
        }

        // subtraction of secret key
        asm volatile ("sub.cc.u32 %0, %0, %1;": "+r"(r[0]): "r"(sk[0]));

#pragma unroll
        for (int i = 1; i < 8; ++i)
        {
            asm volatile ("subc.cc.u32 %0, %0, %1;": "+r"(r[i]): "r"(sk[i]));
        }

        asm volatile ("subc.u32 %0, %0, 0;": "+r"(r[8]));

    //===================================================================//
    //  Result mod Q
    //===================================================================//
        // 20 bytes
        uint32_t * med = ind;
        // 4 bytes
        uint32_t * d = ind + 5; 
        uint32_t * carry = d;

        d[0] = r[8];

    //====================================================================//
        asm volatile ("mul.lo.u32 %0, %1, "q0_s";": "=r"(med[0]): "r"(*d));
        asm volatile ("mul.hi.u32 %0, %1, "q0_s";": "=r"(med[1]): "r"(*d));
        asm volatile ("mul.lo.u32 %0, %1, "q2_s";": "=r"(med[2]): "r"(*d));
        asm volatile ("mul.hi.u32 %0, %1, "q2_s";": "=r"(med[3]): "r"(*d));

        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q1_s", %0;": "+r"(med[1]): "r"(*d)
        );

        asm volatile (
            "madc.hi.cc.u32 %0, %1, "q1_s", %0;": "+r"(med[2]): "r"(*d)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;": "+r"(med[3]): "r"(*d)
        );

        asm volatile ("madc.hi.u32 %0, %1, "q3_s", 0;": "=r"(med[4]): "r"(*d));

    //====================================================================//
        asm volatile ("sub.cc.u32 %0, %0, %1;": "+r"(r[0]): "r"(med[0]));

#pragma unroll
        for (int i = 1; i < 5; ++i)
        {
            asm volatile ("subc.cc.u32 %0, %0, %1;": "+r"(r[i]): "r"(med[i]));
        }

#pragma unroll
        for (int i = 5; i < 7; ++i)
        {
            asm volatile ("subc.cc.u32 %0, %0, 0;": "+r"(r[i]));
        }

        asm volatile ("subc.u32 %0, %0, 0;": "+r"(r[7]));

    //====================================================================//
        d[1] = d[0] >> 31;
        d[0] <<= 1;

        asm volatile ("add.cc.u32 %0, %0, %1;": "+r"(r[4]): "r"(d[0]));
        asm volatile ("addc.cc.u32 %0, %0, %1;": "+r"(r[5]): "r"(d[1]));
        asm volatile ("addc.cc.u32 %0, %0, 0;": "+r"(r[6]));
        asm volatile ("addc.u32 %0, %0, 0;": "+r"(r[7]));

    //====================================================================//
        asm volatile ("sub.cc.u32 %0, %0, "q0_s";": "+r"(r[0]));
        asm volatile ("subc.cc.u32 %0, %0, "q1_s";": "+r"(r[1]));
        asm volatile ("subc.cc.u32 %0, %0, "q2_s";": "+r"(r[2]));
        asm volatile ("subc.cc.u32 %0, %0, "q3_s";": "+r"(r[3]));
        asm volatile ("subc.cc.u32 %0, %0, "q4_s";": "+r"(r[4]));

#pragma unroll
        for (int i = 5; i < 8; ++i)
        {
            asm volatile ("subc.cc.u32 %0, %0, "qhi_s";": "+r"(r[i]));
        }

        asm volatile ("subc.u32 %0, 0, 0;": "=r"(*carry));

        *carry = 0 - *carry;

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q0_s", %0;": "+r"(r[0]): "r"(*carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q1_s", %0;": "+r"(r[1]): "r"(*carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q2_s", %0;": "+r"(r[2]): "r"(*carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;": "+r"(r[3]): "r"(*carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q4_s", %0;": "+r"(r[4]): "r"(*carry)
        );

#pragma unroll
        for (int i = 5; i < 7; ++i)
        {
            asm volatile (
                "madc.lo.cc.u32 %0, %1, "qhi_s", %0;": "+r"(r[i]): "r"(*carry)
            );
        }

        asm volatile (
            "madc.lo.u32 %0, %1, "qhi_s", %0;": "+r"(r[7]): "r"(*carry)
        );

    //===================================================================//
    //  Dump result to global memory -- LITTLE ENDIAN
    //===================================================================//
        j = ((uint64_t *)r)[3] < ((uint64_t *)bound)[3]
            || ((uint64_t *)r)[3] == ((uint64_t *)bound)[3] && (
                ((uint64_t *)r)[2] < ((uint64_t *)bound)[2]
                || ((uint64_t *)r)[2] == ((uint64_t *)bound)[2] && (
                    ((uint64_t *)r)[1] < ((uint64_t *)bound)[1]
                    || ((uint64_t *)r)[1] == ((uint64_t *)bound)[1]
                    && ((uint64_t *)r)[0] <= ((uint64_t *)bound)[0]
                )
            );

        valid[tid] = (1 - !j) * (tid + 1);

#pragma unroll
        for (int i = 0; i < NUM_SIZE_32; ++i)
        {
            res[tid * NUM_SIZE_32 + i] = r[i];
        }

        __syncthreads();
    }

    return;
}

// mining.cu
