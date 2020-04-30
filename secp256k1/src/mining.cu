// mining.cu

/*******************************************************************************

    MINING -- Autolykos parallel BlockMining procedure

*******************************************************************************/

#include "../include/mining.h"
#include <cuda.h>



const __constant__ uint64_t ivals[8] = {  
    0x6A09E667F2BDC928,                                 
    0xBB67AE8584CAA73B,                                 
    0x3C6EF372FE94F82B,                                 
    0xA54FF53A5F1D36F1,                                 
    0x510E527FADE682D1,                                 
    0x9B05688C2B3E6C1F,                                 
    0x1F83D9ABFB41BD6B,                                 
    0x5BE0CD19137E2179 
};


void cpySkSymbol(uint8_t *skh)
{
    CUDA_CALL(cudaMemcpyToSymbol(sk, skh, NUM_SIZE_32 * sizeof(uint32_t)));
}

void cpyCtxSymbol(ctx_t *ctx)
{
    CUDA_CALL(cudaMemcpyToSymbol(ctt, ctx, sizeof(ctx_t)));

}

////////////////////////////////////////////////////////////////////////////////
//  Unfinalized hash of message
////////////////////////////////////////////////////////////////////////////////

void InitMining(
    // context
    ctx_t * ctx,
    // message
    const uint32_t * mes,
    // message length in bytes
    const uint32_t meslen
)
{
    uint64_t aux[32];

    //========================================================================//
    //  Initialize context
    //========================================================================//
    memset(ctx->b, 0, BUF_SIZE_8);
    B2B_IV(ctx->h);
    ctx->h[0] ^= 0x01010000 ^ NUM_SIZE_8;
    memset(ctx->t, 0, 16);
    ctx->c = 0;

    //========================================================================//
    //  Hash message
    //========================================================================//
    for (uint_t j = 0; j < meslen; ++j)
    {
        if (ctx->c == BUF_SIZE_8) { HOST_B2B_H(ctx, aux); }

        ctx->b[ctx->c++] = ((const uint8_t *)mes)[j];
    }
    ((uint32_t*)(ctx->t))[0] = 40;
    ctx->c = 40;

    return;
}



__global__ void BlakeHash(const uint32_t* data, const uint64_t base, uint32_t* BHashes)
{
    uint32_t tid;

    uint64_t aux[32];

    ctx_t * ctx = ctt;
    uint32_t j;
    uint32_t non[NONCE_SIZE_32];
#pragma unroll
    for(int ii = 0; ii < 4; ii++)
    {
        tid = (NONCES_PER_ITER/4)*ii + threadIdx.x + blockDim.x * blockIdx.x;
        
        asm volatile (
            "add.cc.u32 %0, %1, %2;":
            "=r"(non[0]): "r"(((uint32_t *)&base)[0]), "r"(tid)
        );

        asm volatile (
            "addc.u32 %0, %1, 0;": "=r"(non[1]): "r"(((uint32_t *)&base)[1])
        );

        uint64_t tmp;
        ((uint32_t*)(&tmp))[0] = __byte_perm( non[1], 0 , 0x0123);
        ((uint32_t*)(&tmp))[1] = __byte_perm( non[0], 0 , 0x0123);

        B2B_IV(aux);                                                                           
        B2B_IV(aux + 8);                                                           
        aux[0] = ivals[0];                                                               
        ((uint64_t *)(aux))[12] ^= 40;                         
        ((uint64_t *)(aux))[13] ^= 0;       
                                                
        ((uint64_t *)(aux))[14] = ~((uint64_t *)(aux))[14];                        
        
        ((uint64_t *)(aux))[16] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 0];         
        ((uint64_t *)(aux))[17] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 1];         
        ((uint64_t *)(aux))[18] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 2];         
        ((uint64_t *)(aux))[19] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 3];         
        ((uint64_t *)(aux))[20] = tmp;         
        ((uint64_t *)(aux))[21] = 0;         
        ((uint64_t *)(aux))[22] = 0 ;      
        ((uint64_t *)(aux))[23] = 0  ;       
        ((uint64_t *)(aux))[24] = 0  ;      
        ((uint64_t *)(aux))[25] = 0  ;     
        ((uint64_t *)(aux))[26] = 0  ;       
        ((uint64_t *)(aux))[27] = 0  ;       
        ((uint64_t *)(aux))[28] = 0  ;      
        ((uint64_t *)(aux))[29] = 0  ;       
        ((uint64_t *)(aux))[30] = 0  ;      
        ((uint64_t *)(aux))[31] = 0  ;       
                                                                                    
        B2B_MIX(aux, aux + 16);                                                    

        uint64_t hsh;
        #pragma unroll
        for(j = 0; j < NUM_SIZE_32; j+=2)
        {
            hsh = ivals[j >> 1];
            hsh ^= ((uint64_t *)(aux))[j >> 1] ^ ((uint64_t *)(aux))[ 8 + (j >> 1)];
            BHashes[THREADS_PER_ITER*j + tid] = __byte_perm( ((uint32_t*)(&hsh))[0], 0 , 0x0123);
            BHashes[THREADS_PER_ITER*(j+1) + tid] = __byte_perm( ((uint32_t*)(&hsh))[1], 0 , 0x0123);

        }

    }
}


////////////////////////////////////////////////////////////////////////////////
//  Block mining                                                               
////////////////////////////////////////////////////////////////////////////////
__global__ void BlockMining(
    // boundary for puzzle
    const uint32_t * __restrict__ bound,
    // precalculated hashes
    const uint32_t * __restrict__ hashes,
    const uint32_t * __restrict__ data,
    // results
    uint32_t * res,
    // indices of valid solutions
    uint32_t * valid,
    uint32_t * BHashes
)
{
    uint32_t tid = threadIdx.x;

 
    uint32_t r[9];

    uint32_t indices[32];
    uint32_t *tmparr = indices + 2;    
    uint32_t *i1 = indices;
    
    #pragma unroll
    for(int ii = 0; ii < 1; ii++)
    {
        tid = ii*(THREADS_PER_ITER/4) + threadIdx.x + blockDim.x * blockIdx.x;
   
        uint32_t j;
        i1[0] = ( (BHashes[tid]) & N_MASK) << 3;
        i1[1] = ((( BHashes[tid] << 8) | (BHashes[THREADS_PER_ITER + tid] >> 24)) & N_MASK) << 3;
        
        #pragma unroll
        for (uint32_t k = 2; k < K_LEN-4; ++k)
        {
            i1[k] = (__funnelshift_l( BHashes[ ((k>>2) + 1)*THREADS_PER_ITER + tid], BHashes[(k>>2)*THREADS_PER_ITER + tid], ((k%4) << 3) ) & N_MASK) << 3;
        }
        #pragma unroll         
        for (uint32_t k = K_LEN-4; k < K_LEN; ++k)
        {
            i1[k] = (__funnelshift_l( BHashes[ tid], BHashes[(k>>2)*THREADS_PER_ITER + tid], ((k%4) << 3) ) & N_MASK) << 3;
        }
        
        asm volatile (
            "add.cc.u32 %0, %1, %2;":
            "=r"(r[6]): "r"(hashes[i1[0] + 6]), "r"(hashes[i1[1] + 6])
        );

        #pragma unroll
        for (int i = 7; i < 8; ++i)
        {
            asm volatile (
                "addc.cc.u32 %0, %1, %2;":
                "=r"(r[i]):
                "r"(hashes[i1[0] + i]),
                "r"(hashes[i1[1] + i])
            );
        }

        asm volatile ("addc.u32 %0, 0, 0;": "=r"(r[8]));
        
        // remaining additions
        #pragma unroll
        for (uint32_t k = 2; k < K_LEN-4; ++k)
        {

            asm volatile (
                "add.cc.u32 %0, %0, %1;":
                "+r"(r[6]): "r"(hashes[i1[k] + 6])
            );

            #pragma unroll
            for (int i = 7; i < 8; ++i)
            {
                asm volatile (
                    "addc.cc.u32 %0, %0, %1;":
                    "+r"(r[i]): "r"(hashes[i1[k]+i])
                );
            }

            asm volatile ("addc.u32 %0, %0, 0;": "+r"(r[8]));
        }

        #pragma unroll
        for (uint32_t k = K_LEN-4; k < K_LEN; ++k)
        {
            asm volatile (
                "add.cc.u32 %0, %0, %1;":
                "+r"(r[6]): "r"(hashes[i1[k] + 6])
            );

            #pragma unroll
            for (int i = 7; i < 8; ++i)
            {
                asm volatile (
                    "addc.cc.u32 %0, %0, %1;":
                    "+r"(r[i]): "r"(hashes[i1[k]+i])
                );
            }

            asm volatile ("addc.u32 %0, %0, 0;": "+r"(r[8]));
        }

        // subtraction of secret key
        asm volatile ("sub.cc.u32 %0, %0, %1;": "+r"(r[6]): "r"(sk[6]));

        #pragma unroll
        for (int i = 7; i < 8; ++i)
        {
            asm volatile (
                "subc.cc.u32 %0, %0, %1;": "+r"(r[i]): "r"(sk[i])
            );
        }

        asm volatile ("subc.u32 %0, %0, 0;": "+r"(r[8]));



        if((r[6] <= bound[6] && r[7] == 0)  || (r[7] == 0xFFFFFFFF && r[6] > 0xFFFFFFFF - 0x20))
        {

            asm volatile (
                "add.cc.u32 %0, %1, %2;":
                "=r"(r[0]): "r"(hashes[i1[0]]), "r"(hashes[i1[1]])
            );

            #pragma unroll
            for (int i = 1; i < 8; ++i)
            {
                asm volatile (
                    "addc.cc.u32 %0, %1, %2;":
                    "=r"(r[i]):
                    "r"(hashes[i1[0] + i]),
                    "r"(hashes[i1[1] + i])
                );
            }

            asm volatile ("addc.u32 %0, 0, 0;": "=r"(r[8]));
          
            // remaining additions
            #pragma unroll
            for (uint32_t k = 2; k < K_LEN-4; ++k)
            {

                asm volatile (
                    "add.cc.u32 %0, %0, %1;":
                    "+r"(r[0]): "r"(hashes[i1[k]])
                );

                #pragma unroll
                for (int i = 1; i < 8; ++i)
                {
                    asm volatile (
                        "addc.cc.u32 %0, %0, %1;":
                        "+r"(r[i]): "r"(hashes[i1[k]+i])
                    );
                }

                asm volatile ("addc.u32 %0, %0, 0;": "+r"(r[8]));
            }

            #pragma unroll
            for (uint32_t k = K_LEN-4; k < K_LEN; ++k)
            {

                asm volatile (
                    "add.cc.u32 %0, %0, %1;":
                    "+r"(r[0]): "r"(hashes[i1[k]])
                );

                #pragma unroll
                for (int i = 1; i < 8; ++i)
                {
                    asm volatile (
                        "addc.cc.u32 %0, %0, %1;":
                        "+r"(r[i]): "r"(hashes[i1[k]+i])
                    );
                }

                asm volatile ("addc.u32 %0, %0, 0;": "+r"(r[8]));
            }



            // subtraction of secret key
            asm volatile ("sub.cc.u32 %0, %0, %1;": "+r"(r[0]): "r"(sk[0]));

            #pragma unroll
            for (int i = 1; i < 8; ++i)
            {
                asm volatile (
                    "subc.cc.u32 %0, %0, %1;": "+r"(r[i]): "r"(sk[i])
                );
            }

            asm volatile ("subc.u32 %0, %0, 0;": "+r"(r[8]));

            //================================================================//
            //  Result mod Q
            //================================================================//
            // 20 bytes
            uint32_t * med = tmparr;
            // 4 bytes
            uint32_t * d = i1; 
            uint32_t * carry = d;
            //uint32_t *d = 
            d[0] = r[8];

            //================================================================//
            asm volatile (
                "mul.lo.u32 %0, %1, " q0_s ";": "=r"(med[0]): "r"(*d)
            );

            asm volatile (
                "mul.hi.u32 %0, %1, " q0_s ";": "=r"(med[1]): "r"(*d)
            );

            asm volatile (
                "mul.lo.u32 %0, %1, " q2_s ";": "=r"(med[2]): "r"(*d)
            );

            asm volatile (
                "mul.hi.u32 %0, %1, " q2_s ";": "=r"(med[3]): "r"(*d)
            );

            asm volatile (
                "mad.lo.cc.u32 %0, %1, " q1_s ", %0;": "+r"(med[1]): "r"(*d)
            );

            asm volatile (
                "madc.hi.cc.u32 %0, %1, " q1_s ", %0;": "+r"(med[2]): "r"(*d)
            );

            asm volatile (
                "madc.lo.cc.u32 %0, %1, " q3_s ", %0;": "+r"(med[3]): "r"(*d)
            );

            asm volatile (
                "madc.hi.u32 %0, %1, " q3_s ", 0;": "=r"(med[4]): "r"(*d)
            );

            //================================================================//
            asm volatile ("sub.cc.u32 %0, %0, %1;": "+r"(r[0]): "r"(med[0]));

#pragma unroll
            for (int i = 1; i < 5; ++i)
            {
                asm volatile (
                    "subc.cc.u32 %0, %0, %1;": "+r"(r[i]): "r"(med[i])
                );
            }

#pragma unroll
            for (int i = 5; i < 7; ++i)
            {
                asm volatile ("subc.cc.u32 %0, %0, 0;": "+r"(r[i]));
            }

            asm volatile ("subc.u32 %0, %0, 0;": "+r"(r[7]));

            //================================================================//
            d[1] = d[0] >> 31;
            d[0] <<= 1;

            asm volatile ("add.cc.u32 %0, %0, %1;": "+r"(r[4]): "r"(d[0]));
            asm volatile ("addc.cc.u32 %0, %0, %1;": "+r"(r[5]): "r"(d[1]));
            asm volatile ("addc.cc.u32 %0, %0, 0;": "+r"(r[6]));
            asm volatile ("addc.u32 %0, %0, 0;": "+r"(r[7]));

            //================================================================//
            asm volatile ("sub.cc.u32 %0, %0, " q0_s ";": "+r"(r[0]));
            asm volatile ("subc.cc.u32 %0, %0, " q1_s ";": "+r"(r[1]));
            asm volatile ("subc.cc.u32 %0, %0, " q2_s ";": "+r"(r[2]));
            asm volatile ("subc.cc.u32 %0, %0, " q3_s ";": "+r"(r[3]));
            asm volatile ("subc.cc.u32 %0, %0, " q4_s ";": "+r"(r[4]));

#pragma unroll
            for (int i = 5; i < 8; ++i)
            {
                asm volatile ("subc.cc.u32 %0, %0, " qhi_s ";": "+r"(r[i]));
            }

            asm volatile ("subc.u32 %0, 0, 0;": "=r"(*carry));

            *carry = 0 - *carry;

            //================================================================//
            asm volatile (
                "mad.lo.cc.u32 %0, %1, " q0_s ", %0;": "+r"(r[0]): "r"(*carry)
            );

            asm volatile (
                "madc.lo.cc.u32 %0, %1, " q1_s ", %0;": "+r"(r[1]): "r"(*carry)
            );

            asm volatile (
                "madc.lo.cc.u32 %0, %1, " q2_s ", %0;": "+r"(r[2]): "r"(*carry)
            );

            asm volatile (
                "madc.lo.cc.u32 %0, %1, " q3_s ", %0;": "+r"(r[3]): "r"(*carry)
            );

            asm volatile (
                "madc.lo.cc.u32 %0, %1, " q4_s ", %0;": "+r"(r[4]): "r"(*carry)
            );

#pragma unroll
            for (int i = 5; i < 7; ++i)
            {
                asm volatile (
                    "madc.lo.cc.u32 %0, %1, " qhi_s ", %0;":
                    "+r"(r[i]): "r"(*carry)
                );
            }

            asm volatile (
                "madc.lo.u32 %0, %1, " qhi_s ", %0;": "+r"(r[7]): "r"(*carry)
            );

            //================================================================//
            //  Dump result to global memory -- LITTLE ENDIAN
            //================================================================//
            j = ((uint64_t *)r)[3] < ((uint64_t *)bound)[3]
                || ((uint64_t *)r)[3] == ((uint64_t *)bound)[3] && (
                    ((uint64_t *)r)[2] < ((uint64_t *)bound)[2]
                    || ((uint64_t *)r)[2] == ((uint64_t *)bound)[2] && (
                        ((uint64_t *)r)[1] < ((uint64_t *)bound)[1]
                        || ((uint64_t *)r)[1] == ((uint64_t *)bound)[1]
                        && ((uint64_t *)r)[0] < ((uint64_t *)bound)[0]
                    )
                );

            

            if(j)
            {

                
                valid[0] = tid+1; 
                #pragma unroll
                for (int i = 0; i < NUM_SIZE_32; ++i)
                {
                    res[i] = r[i];
                }

            }
            
        
        }
        
    }

  
}

// mining.cu
