#include "kernel.h"

// 8 * 32 bits
// q == [q0, q1, q2, q3, 0, 0, 0, 0x10000000]

// 32 bits
#define q3_s "0x14def9de"
#define q2_s "0xa2f79cd6"
#define q1_s "0x5812631a"
#define q0_s "0x5cf5d3ed"

////////////////////////////////////////////////////////////////////////////////
//  256 bits addition with overflow
////////////////////////////////////////////////////////////////////////////////
// [x, carry] = [x, carry] + y
__global__ void add(
    // 8 * 32 bits
    uint32_t * x,
    // 1 * 32 bits
    uint32_t * carry,
    // 8 * 32 bits
    uint32_t * y
) {
    asm volatile (
        "add.cc.u32 %0, %0, %1;":
        "+r"(x[0]):
        "r"(y[0])
    );

#pragma unroll
    for (int i = 1; i < 8; ++i)
    {
        asm volatile (
            "addc.cc.u32 %0, %0, %1;":
            "+r"(x[i]):
            "r"(y[i])
        );
    }

    asm volatile (
        "addc.u32 %0, %0, 0;":
        "+r"(*carry)
    );
}

////////////////////////////////////////////////////////////////////////////////
//  256 bits subtraction with borrow-out
////////////////////////////////////////////////////////////////////////////////
// [x, carry] = [x, carry] - y
__global__ void sub(
    // 8 * 32 bits
    uint32_t * x,
    // 1 * 32 bits
    uint32_t * carry,
    // 8 * 32 bits
    uint32_t * y
) {
    asm volatile (
        "sub.cc.u32 %0, %0, %1;":
        "+r"(x[0]):
        "r"(y[0])
    );

#pragma unroll
    for (int i = 1; i < 8; ++i)
    {
        asm volatile (
            "subc.cc.u32 %0, %0, %1;":
            "+r"(x[i]):
            "r"(y[i])
        );
    }

    asm volatile (
        "subc.u32 %0, %0, 0;":
        "+r"(*carry)
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
    for (int k = 0; k < 8; k += 2)
    {
        asm volatile (
            "mul.lo.u32 %0, %1, %2;":
            "=r"(res[k]):
            "r"(x[0]),
            "r"(y[k])
        );
        asm volatile (
            "mul.hi.u32 %0, %1, %2;":
            "=r"(res[k + 1]):
            "r"(x[0]),
            "r"(y[k])
        );
    }

    //====================================================================//
    asm volatile (
        "mad.lo.cc.u32 %0, %1, %2, %0;":
        "+r"(res[1]):
        "r"(x[0]),
        "r"(y[1])
    );
    asm volatile (
        "madc.hi.cc.u32 %0, %1, %2, %0;":
        "+r"(res[2]):
        "r"(x[0]),
        "r"(y[1])
    );

#pragma unroll
    for (int k = 3; k < 6; k += 2)
    {
        asm volatile (
            "madc.lo.cc.u32 %0, %1, %2, %0;":
            "+r"(res[k]):
            "r"(x[0]),
            "r"(y[k])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(res[k + 1]):
            "r"(x[0]),
            "r"(y[k])
        );
    }

    asm volatile (
        "madc.lo.cc.u32 %0, %1, %2, %0;":
        "+r"(res[7]):
        "r"(x[0]),
        "r"(y[7])
    );
    // initialize res[8]
    asm volatile (
        "madc.hi.u32 %0, %1, %2, 0;":
        "=r"(res[8]):
        "r"(x[0]),
        "r"(y[7])
    );

    //====================================================================//
    //  x[i] * y -> res[i, ..., i + 7, i + 8]
    //====================================================================//
#pragma unroll
    for (int i = 1; i < 8; ++i)
    {
        asm volatile (
            "mad.lo.cc.u32 %0, %1, %2, %0;":
            "+r"(res[i]):
            "r"(x[i]),
            "r"(y[0])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(res[i + 1]):
            "r"(x[i]),
            "r"(y[0])
        );

#pragma unroll
        for (int k = 2; k < 8; k += 2)
        {
            asm volatile (
                "madc.lo.cc.u32 %0, %1, %2, %0;":
                "+r"(res[i + k]):
                "r"(x[i]),
                "r"(y[k])
            );
            asm volatile (
                "madc.hi.cc.u32 %0, %1, %2, %0;":
                "+r"(res[i + k + 1]):
                "r"(x[i]),
                "r"(y[k])
            );
        }

    // initialize res[i + 8]
        asm volatile (
            "addc.u32 %0, 0, 0;":
            "=r"(res[i + 8])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, %2, %0;":
            "+r"(res[i + 1]):
            "r"(x[i]),
            "r"(y[1])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, %2, %0;":
            "+r"(res[i + 2]):
            "r"(x[i]),
            "r"(y[1])
        );

#pragma unroll
        for (int k = 3; k < 6; k += 2)
        {
            asm volatile (
                "madc.lo.cc.u32 %0, %1, %2, %0;":
                "+r"(res[i + k]):
                "r"(x[i]),
                "r"(y[k])
            );
            asm volatile (
                "madc.hi.cc.u32 %0, %1, %2, %0;":
                "+r"(res[i + k + 1]):
                "r"(x[i]),
                "r"(y[k])
            );
        }

        asm volatile (
            "madc.lo.cc.u32 %0, %1, %2, %0;":
            "+r"(res[i + 7]):
            "r"(x[i]),
            "r"(y[7])
        );
        asm volatile (
            "madc.hi.u32 %0, %1, %2, %0;":
            "+r"(res[i + 8]):
            "r"(x[i]),
            "r"(y[7])
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
    uint64_t h;
    uint32_t med[6];
    uint32_t carry;

    for (int i = xw - 1; i >= 4; --i)
    {
        h = ((x[i] << 4) | (x[i - 1] >> 60)) - (x[i] >> 60);

        // correct highest 2 * 32 bits
        ((uint32_t *)(x + i - 1))[1]
            = (((uint32_t *)(x + i - 1))[1] & 0x0FFFFFFF)
            | (((uint32_t *)(x + i))[1] & 0x10000000);

    //====================================================================//
    //  q multiple for next 6 * 32 bits
    //====================================================================//
        asm volatile (
            "mul.lo.u32 %0, %1, "q0_s";":
            "=r"(med[0]):
            "r"(((uint32_t *)&h)[0])
        );
        asm volatile (
            "mul.hi.u32 %0, %1, "q0_s";":
            "=r"(med[1]):
            "r"(((uint32_t *)&h)[0])
        );
        asm volatile (
            "mul.lo.u32 %0, %1, "q2_s";":
            "=r"(med[2]):
            "r"(((uint32_t *)&h)[0])
        );
        asm volatile (
            "mul.hi.u32 %0, %1, "q2_s";":
            "=r"(med[3]):
            "r"(((uint32_t *)&h)[0])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q1_s", %0;":
            "+r"(med[1]):
            "r"(((uint32_t *)&h)[0])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, "q1_s", %0;":
            "+r"(med[2]):
            "r"(((uint32_t *)&h)[0])
        );
        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;":
            "+r"(med[3]):
            "r"(((uint32_t *)&h)[0])
        );
        asm volatile (
            "madc.hi.u32 %0, %1, "q3_s", 0;":
            "=r"(med[4]):
            "r"(((uint32_t *)&h)[0])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q0_s", %0;":
            "+r"(med[1]):
            "r"(((uint32_t *)&h)[1])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, "q0_s", %0;":
            "+r"(med[2]):
            "r"(((uint32_t *)&h)[1])
        );
        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q2_s", %0;":
            "+r"(med[3]):
            "r"(((uint32_t *)&h)[1])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1," q2_s", %0;":
            "+r"(med[4]):
            "r"(((uint32_t *)&h)[1])
        );
        asm volatile (
            "addc.u32 %0, 0, 0;":
            "=r"(med[5])
        );

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q1_s", %0;":
            "+r"(med[2]):
            "r"(((uint32_t *)&h)[1])
        );
        asm volatile (
            "madc.hi.cc.u32 %0, %1, "q1_s", %0;":
            "+r"(med[3]):
            "r"(((uint32_t *)&h)[1])
        );
        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;":
            "+r"(med[4]):
            "r"(((uint32_t *)&h)[1])
        );
        asm volatile (
            "madc.hi.u32 %0, %1, "q3_s", %0;":
            "+r"(med[5]):
            "r"(((uint32_t *)&h)[1])
        );

    //====================================================================//
    //  next 6 * 32 bits mod q
    //====================================================================//
        asm volatile (
            "sub.cc.u32 %0, %0, %1;":
            "+r"(((uint32_t *)(x + i - 4))[0]):
            "r"(med[0])
        );
        asm volatile (
            "subc.cc.u32 %0, %0, %1;":
            "+r"(((uint32_t *)(x + i - 4))[1]):
            "r"(med[1])
        );

#pragma unroll
        for (int j = 1; j < 3; ++j)
        {
#pragma unroll
            for (int k = 0; k < 2; ++k)
            {
                asm volatile (
                    "subc.cc.u32 %0, %0, %1;":
                    "+r"(((uint32_t *)(x + i - 4 + j))[k]):
                    "r"(med[2 * j + k])
                );
            }
        }

        asm volatile (
            "subc.cc.u32 %0, %0, 0;":
            "+r"(((uint32_t *)(x + i - 1))[0])
        );

        asm volatile (
            "subc.cc.u32 %0, %0, 0;":
            "+r"(((uint32_t *)(x + i - 1))[1])
        );

    //====================================================================//
    //  next 6 * 32 bits correction
    //====================================================================//
        asm volatile (
            "subc.u32 %0, 0, 0;":
            "=r"(carry)
        );

        carry = 0 - carry;

    //====================================================================//
        asm volatile (
            "mad.lo.cc.u32 %0, %1, "q0_s", %0;":
            "+r"(((uint32_t *)(x + i - 4))[0]):
            "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q1_s", %0;":
            "+r"(((uint32_t *)(x + i - 4))[1]):
            "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q2_s", %0;":
            "+r"(((uint32_t *)(x + i - 3))[0]):
            "r"(carry)
        );

        asm volatile (
            "madc.lo.cc.u32 %0, %1, "q3_s", %0;":
            "+r"(((uint32_t *)(x + i - 3))[1]):
            "r"(carry)
        );
    //====================================================================//

        asm volatile (
            "addc.cc.u32 %0, %0, 0;":
            "+r"(((uint32_t *)(x + i - 2))[0])
        );

        asm volatile (
            "addc.cc.u32 %0, %0, 0;":
            "+r"(((uint32_t *)(x + i - 2))[1])
        );

        asm volatile (
            "addc.cc.u32 %0, %0, 0;":
            "+r"(((uint32_t *)(x + i - 1))[0])
        );

        asm volatile (
            "addc.u32 %0, %0, 0;":
            "+r"(((uint32_t *)(x + i - 1))[1])
        );
    }
}
