#include "kernel.h"

// 8 * 32 bits
// little-endian
// q == [q0, q1, q2, q3, 0, 0, 0, 0x10000000]

// 32 bits
#define q3_s "0x14DEF9DE"
#define q2_s "0xA2F79CD6"
#define q1_s "0x5812631A"
#define q0_s "0x5CF5D3ED"

////////////////////////////////////////////////////////////////////////////////
//  256 bits addition with overflow
////////////////////////////////////////////////////////////////////////////////
// carry must be initialized
// [x, carry] + y -> [x, carry]
__global__ void addc(
    // 8 * 32 bits
    uint32_t * x,
    // 1 * 32 bits
    uint32_t * carry,
    // 8 * 32 bits
    uint32_t * y
) {
    asm volatile (
        "add.cc.u32 %0, %0, %1;": "+r"(x[0]): "r"(y[0])
    );

#pragma unroll
    for (int i = 1; i < 8; ++i)
    {
        asm volatile (
            "addc.cc.u32 %0, %0, %1;": "+r"(x[i]): "r"(y[i])
        );
    }

    asm volatile (
        "addc.u32 %0, %0, 0;": "+r"(*carry)
    );
}

////////////////////////////////////////////////////////////////////////////////
//  256 bits subtraction with borrow-out
////////////////////////////////////////////////////////////////////////////////
// carry must be initialized
// [x, carry] - y -> [x, carry]
__global__ void subc(
    // 8 * 32 bits
    uint32_t * x,
    // 1 * 32 bits
    uint32_t * carry,
    // 8 * 32 bits
    uint32_t * y
) {
    asm volatile (
        "sub.cc.u32 %0, %0, %1;": "+r"(x[0]): "r"(y[0])
    );

#pragma unroll
    for (int i = 1; i < 8; ++i)
    {
        asm volatile (
            "subc.cc.u32 %0, %0, %1;": "+r"(x[i]): "r"(y[i])
        );
    }

    asm volatile (
        "subc.u32 %0, %0, 0;": "+r"(*carry)
    );
}

////////////////////////////////////////////////////////////////////////////////
//  256 bits multiplication
////////////////////////////////////////////////////////////////////////////////
__global__ void mul(
    // 8 * 32 bits
    uint32_t * x,
    // 8 * 32 bits
    uint32_t * y,
    // 16 * 32 bits
    uint32_t * res
) {
    //====================================================================//
    //  x[0] * y -> res[0, ..., 7, 8]
    //====================================================================//
    // initialize res[0, ..., 7]
#pragma unroll
    for (int j = 0; j < 8; j += 2)
    {
        asm volatile (
            "mul.lo.u32 %0, %1, %2;": "=r"(res[j]): "r"(x[0]), "r"(y[j])
        );
        asm volatile (
            "mul.hi.u32 %0, %1, %2;": "=r"(res[j + 1]): "r"(x[0]), "r"(y[j])
        );
    }

    //====================================================================//
    asm volatile (
        "mad.lo.cc.u32 %0, %1, %2, %0;": "+r"(res[1]): "r"(x[0]), "r"(y[1])
    );
    asm volatile (
        "madc.hi.cc.u32 %0, %1, %2, %0;": "+r"(res[2]): "r"(x[0]), "r"(y[1])
    );

#pragma unroll
    for (int j = 3; j < 6; j += 2)
    {
        asm volatile (
            "madc.lo.cc.u32 %0, %1, %2, %0;": "+r"(res[j]): "r"(x[0]), "r"(y[j])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(res[j + 1]): "r"(x[0]), "r"(y[j])
        );
    }

    asm volatile (
        "madc.lo.cc.u32 %0, %1, %2, %0;": "+r"(res[7]): "r"(x[0]), "r"(y[7])
    );
    // initialize res[8]
    asm volatile (
        "madc.hi.u32 %0, %1, %2, 0;": "=r"(res[8]): "r"(x[0]), "r"(y[7])
    );

    //====================================================================//
    //  x[i] * y -> res[i, ..., i + 7, i + 8]
    //====================================================================//
#pragma unroll
    for (int i = 1; i < 8; ++i)
    {
        asm volatile (
            "mad.lo.cc.u32 %0, %1, %2, %0;": "+r"(res[i]): "r"(x[i]), "r"(y[0])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(res[i + 1]): "r"(x[i]), "r"(y[0])
        );

#pragma unroll
        for (int j = 2; j < 8; j += 2)
        {
            asm volatile (
                "madc.lo.cc.u32 %0, %1, %2, %0;":
                "+r"(res[i + j]): "r"(x[i]), "r"(y[j])
            );
            asm volatile (
                "madc.hi.cc.u32 %0, %1, %2, %0;":
                "+r"(res[i + j + 1]): "r"(x[i]), "r"(y[j])
            );
        }

    // initialize res[i + 8]
        asm volatile (
            "addc.u32 %0, 0, 0;": "=r"(res[i + 8])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, %2, %0;":
            "+r"(res[i + 1]): "r"(x[i]), "r"(y[1])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(res[i + 2]): "r"(x[i]), "r"(y[1])
        );

#pragma unroll
        for (int j = 3; j < 6; j += 2)
        {
            asm volatile (
                "madc.lo.cc.u32 %0, %1, %2, %0;":
                "+r"(res[i + j]): "r"(x[i]), "r"(y[j])
            );
            asm volatile (
                "madc.hi.cc.u32 %0, %1, %2, %0;":
                "+r"(res[i + j + 1]): "r"(x[i]), "r"(y[j])
            );
        }

        asm volatile (
            "madc.lo.cc.u32 %0, %1, %2, %0;":
            "+r"(res[i + 7]): "r"(x[i]), "r"(y[7])
        );
        asm volatile (
            "madc.hi.u32 %0, %1, %2, %0;":
            "+r"(res[i + 8]): "r"(x[i]), "r"(y[7])
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
//  Mod q
////////////////////////////////////////////////////////////////////////////////
__global__ void mod_q(
    // word count
    uint32_t xw,
    // xw * 64 bits
    uint64_t * x
    // result 4 * 64 bits -> x[0, 1, 2, 3]
) {
    uint32_t * y = (uint32_t *)x; 
    uint32_t d[2]; 
    uint32_t med[6];
    uint32_t carry;

    for (int i = (xw - 1) << 1; i >= 8; i -= 2)
    {
        *((uint64_t *)d) = ((x[i >> 1] << 4) | (x[(i >> 1) - 1] >> 60))
            - (x[i >> 1] >> 60);

        // correct highest 32 bits
        y[i - 1] = (y[i - 1] & 0x0FFFFFFF) | y[i + 1] & 0x10000000;

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
    //  x[i/2 - 2, i/2 - 3, i/2 - 4] mod q
    //====================================================================//
        asm volatile (
            "sub.cc.u32 %0, %0, %1;": "+r"(y[i - 8]): "r"(med[0])
        );

#pragma unroll
        for (int j = 1; j < 6; ++j)
        {
            asm volatile (
                "subc.cc.u32 %0, %0, %1;": "+r"(y[i + j - 8]): "r"(med[j])
            );
        }

        asm volatile (
            "subc.cc.u32 %0, %0, 0;": "+r"(y[i - 2])
        );

        asm volatile (
            "subc.cc.u32 %0, %0, 0;": "+r"(y[i - 1])
        );

    //====================================================================//
    //  x[i/2 - 2, i/2 - 3, i/2 - 4] correction
    //====================================================================//
        asm volatile (
            "subc.u32 %0, 0, 0;": "=r"(carry)
        );

        carry = 0 - carry;

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q0_s", %0;": "+r"(y[i - 8]): "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q1_s", %0;": "+r"(y[i - 7]): "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q2_s", %0;": "+r"(y[i - 6]): "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;": "+r"(y[i - 5]): "r"(carry)
        );

    //====================================================================//
#pragma unroll
        for (int j = 0; j < 3; ++j)
        {
            asm volatile (
                "addc.cc.u32 %0, %0, 0;": "+r"(y[i + j - 4])
            );
        }

        asm volatile (
            "addc.u32 %0, %0, 0;": "+r"(y[i - 1])
        );
    }
}
