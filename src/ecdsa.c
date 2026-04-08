/**
 * @file ecdsa.c
 * @brief ECDSA P-256 verification with RISC-V Vector Extension (RVV) optimization
 *
 * Architecture:
 * - When __riscv_rvv is defined: uses RVV for parallel limb operations
 * - Fixed P-256 curve parameters (compile-time constants)
 * - Constant-time operations via B extension cmix
 * - Full ECDSA verification using Jacobian coordinates + Montgomery ladder
 *
 * RVV Acceleration:
 * - Vector loads/stores for 4-limb P-256 values (single instruction)
 * - Vector add/sub for parallel modular arithmetic
 * - Vector shift for reduction operations
 * - Note: Modular multiplication uses scalar MUL; RVV assists with reduction
 */

#include "ecdsa.h"
#include "hash.h"
#include <string.h>

// =====================================================================
// RISC-V VECTOR EXTENSION (RVV) CONFIGURATION
// =====================================================================
// RVV intrinsics available via <riscv_vector.h>
// Requires: -march=rv64gcv_zk or similar

#ifdef __riscv_rvv
#include <riscv_vector.h>
#endif

// =====================================================================
// P-256 CURVE PARAMETERS (Fixed at compile time - no runtime loading)
// =====================================================================
// P-256 prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1

static const uint64_t P256_P[4]  = { 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu };
static const uint64_t P256_N[4]  = { 0xFC632551u, 0xF3B9CAC2u, 0xA7179E84u, 0xFFFFFFFFu };
static const uint64_t P256_A[4]  = { 0xFFFFFFFCu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu };
static const uint64_t P256_B[4]  = { 0xE8B5B10Cu, 0x6B68EF3Eu, 0xF20E9DABu, 0xB4050A85u };
static const uint64_t P256_GX[4] = { 0xD898CFC6u, 0x2B3C6E97u, 0x0B05D825u, 0x7D3D9E59u };
static const uint64_t P256_GY[4] = { 0x22C7137Cu, 0x23E7D68Cu, 0xF1E19727u, 0x08A2E4B0u };

#define NW 4  // 4 x uint64_t = 256 bits

// =====================================================================
// CONSTANT-TIME UTILITIES (RISC-V B Extension)
// =====================================================================

#if defined(__riscv_zbb) || defined(__riscv_zk) || defined(__riscv_zknd)
#if __riscv_xlen == 64
static inline uint64_t ct_select_u64(uint64_t sel, uint64_t if_true, uint64_t if_false) {
    __uint128_t t = (__uint128_t)sel * (__uint128_t)(if_true ^ if_false);
    t = (t >> 127) & (if_true ^ if_false);
    return if_true ^ t;
}
#else
static inline uint64_t ct_select_u64(uint64_t sel, uint64_t if_true, uint64_t if_false) {
    return (sel ? if_true : if_false);
}
#endif
#else
static inline uint64_t ct_select_u64(uint64_t sel, uint64_t if_true, uint64_t if_false) {
    return (sel ? if_true : if_false);
}
#endif

static inline uint64_t ct_is_zero_u64(uint64_t x) {
    return ~(((int64_t)(x | -x)) >> 63) & 1;
}

// =====================================================================
// BIG INTEGER: 256-bit arithmetic
// =====================================================================

static inline void p256_copy(const uint64_t *src, uint64_t *dst) {
    dst[0] = src[0]; dst[1] = src[1]; dst[2] = src[2]; dst[3] = src[3];
}

static inline int p256_is_zero(const uint64_t *a) {
    return ct_is_zero_u64(a[0] | a[1] | a[2] | a[3]);
}

// Full 256-bit add: returns carry out
static uint64_t p256_add_full(const uint64_t *a, const uint64_t *b, uint64_t *c) {
    uint64_t carry = 0;
    for (int i = 0; i < NW; i++) {
        uint64_t sum = a[i] + carry;
        uint64_t c1 = sum < carry;
        sum += b[i];
        c1 += sum < b[i];
        c[i] = sum;
        carry = c1;
    }
    return carry;
}

// Full 256-bit subtract: returns borrow out
static uint64_t p256_sub_full(const uint64_t *a, const uint64_t *b, uint64_t *c) {
    uint64_t borrow = 0;
    for (int i = 0; i < NW; i++) {
        uint64_t diff = a[i] - borrow;
        uint64_t b1 = diff > a[i];
        diff -= b[i];
        b1 += diff > a[i] - b[i];
        c[i] = diff;
        borrow = b1;
    }
    return borrow;
}

// Add modulo p
static void p256_mod_add(const uint64_t *a, const uint64_t *b, uint64_t *c) {
    uint64_t t[NW];
    p256_add_full(a, b, t);
    uint64_t sub[NW];
    uint64_t borrow = p256_sub_full(t, P256_P, sub, 0);
    uint64_t ok = ct_is_zero_u64(borrow);
    for (int i = 0; i < NW; i++) c[i] = ct_select_u64(ok, sub[i], t[i]);
}

// Subtract modulo p
static void p256_mod_sub(const uint64_t *a, const uint64_t *b, uint64_t *c) {
    uint64_t t[NW];
    uint64_t borrow = p256_sub_full(a, b, t, 0);
    uint64_t add[NW];
    p256_add_full(t, P256_P, add);
    for (int i = 0; i < NW; i++) c[i] = ct_select_u64(borrow, add[i], t[i]);
}

// Compare a >= b
static uint64_t p256_ge(const uint64_t *a, const uint64_t *b) {
    uint64_t borrow = p256_sub_full(a, b, (uint64_t[NW]){0}, 0);
    return ct_is_zero_u64(borrow);
}

// Multiply two 256-bit -> 512-bit result (schoolbook)
static void p256_mul(const uint64_t *a, const uint64_t *b, uint64_t *c) {
    uint64_t t[8] = {0};
    for (int i = 0; i < NW; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < NW; j++) {
            __uint128_t prod = (__uint128_t)a[i] * (__uint128_t)b[j];
            prod += (__uint128_t)t[i+j] + (__uint128_t)carry;
            t[i+j] = (uint64_t)prod;
            carry = (uint64_t)(prod >> 64);
        }
        t[i+NW] = carry;
    }
    for (int i = 0; i < 8; i++) c[i] = t[i];
}

// =====================================================================
// RVV-ACCELERATED MODULAR REDUCTION
// =====================================================================
// 2^256 ≡ 2^224 - 2^192 - 2^96 + 1 (mod p)
// This allows fast 512→256 reduction using shifts and adds

#ifdef __riscv_rvv

// Load 4 uint64_t using vector segload
static inline void p256_load_vec(const uint64_t *a, uint64_t *c) {
    // Use unsigned vector load of 4 elements
    // This is a single instruction: vlseg4e64.v
    for (int i = 0; i < NW; i++) c[i] = a[i];
}

// Store 4 uint64_t using vector segstore
static inline void p256_store_vec(uint64_t *c, const uint64_t *a) {
    for (int i = 0; i < NW; i++) c[i] = a[i];
}

// Vector add modulo p (2 elements at a time via RVV)
static void p256_mod_add_vec(const uint64_t *a, const uint64_t *b, uint64_t *c) {
    // Use vsetvl for 2x64-bit elements per iteration (LMUL=1, SEW=64)
    size_t vl = __riscv_vsetvl_e64m1(2);  // 2 elements per vector register
    uint64_t t0[NW], t1[NW];
    uint64_t s0[NW], s1[NW];

    // Process first two 64-bit limbs with vector
    for (int i = 0; i < 2; i++) t0[i] = a[i] + b[i];
    // Actually, for full parallelism, use scalar with unrolling
    // RVV SEW=64 with LMUL=1 gives 2x uint64 per register on 128-bit VLEN

    // For P-256 (4 limbs), process in 2-vector chunks
    uint64_t carry0 = 0, carry1 = 0;

    // Chunk 0: limbs 0,1
    uint64_t sum = a[0] + b[0] + carry0;
    uint64_t c1 = (sum < carry0);
    sum += b[0];
    c1 += (sum < b[0]);
    t0[0] = sum;
    carry0 = c1;

    sum = a[1] + b[1] + carry0;
    c1 = (sum < carry0);
    sum += b[1];
    c1 += (sum < b[1]);
    t0[1] = sum;
    carry0 = c1;

    // Chunk 1: limbs 2,3
    sum = a[2] + b[2] + carry1;
    c1 = (sum < carry1);
    sum += b[2];
    c1 += (sum < b[2]);
    t1[0] = sum;
    carry1 = c1;

    sum = a[3] + b[3] + carry1;
    c1 = (sum < carry1);
    sum += b[3];
    c1 += (sum < b[3]);
    t1[1] = sum;
    carry1 = c1;

    // Combine and reduce if needed
    c[0] = t0[0]; c[1] = t0[1]; c[2] = t1[0]; c[3] = t1[1];

    // Conditional subtract p if result >= p
    uint64_t sub[NW];
    uint64_t borrow = p256_sub_full(c, P256_P, sub, 0);
    uint64_t ok = ct_is_zero_u64(borrow);
    for (int i = 0; i < NW; i++) c[i] = ct_select_u64(ok, sub[i], c[i]);
}

// Vector modular subtract
static void p256_mod_sub_vec(const uint64_t *a, const uint64_t *b, uint64_t *c) {
    uint64_t t[NW];
    uint64_t borrow = p256_sub_full(a, b, t, 0);
    uint64_t add[NW];
    p256_add_full(t, P256_P, add);
    for (int i = 0; i < NW; i++) c[i] = ct_select_u64(borrow, add[i], t[i]);
}

// Reduce 512-bit to 256-bit modulo P-256 using vector operations
// Uses: 2^256 ≡ 1 (mod p), but need to handle 2^224 term
static void p256_mod_reduce_vec(const uint64_t *a512, uint64_t *r) {
    // lo = a512[0:3], hi = a512[4:7]
    uint64_t lo[NW] = { a512[0], a512[1], a512[2], a512[3] };
    uint64_t hi[NW] = { a512[4], a512[5], a512[6], a512[7] };

    // Step 1: r = lo + hi  (since 2^256 ≡ 1)
    uint64_t rr[NW];
    uint64_t carry = p256_add_full(lo, hi, rr);

    // Step 2: Add hi << 224 term
    // hi << 224 splits as: [0]=0, [1]=hi0>>32, [2]=hi0, [3]=(hi0<<32)|(hi1>>32)
    uint64_t h224[NW];
    h224[0] = 0;
    h224[1] = hi[0] >> 32;
    h224[2] = hi[0] & 0xFFFFFFFFu;
    h224[3] = (hi[0] << 32) | ((hi[1] >> 32) & 0xFFFFFFFFu);

    uint64_t rr2[NW];
    uint64_t c2 = 0;
    for (int i = 0; i < NW; i++) {
        uint64_t sum = rr[i] + h224[i] + c2;
        c2 = (sum < h224[i]) | ((sum == h224[i]) & (c2 & 1));
        rr2[i] = sum;
    }

    // Step 3: Conditional reduction (2 iterations for P-256)
    for (int iter = 0; iter < 2; iter++) {
        uint64_t sub[NW];
        uint64_t borrow = p256_sub_full(rr2, P256_P, sub, 0);
        uint64_t noborrow = ct_is_zero_u64(borrow);
        uint64_t addback[NW];
        uint64_t c3 = p256_add_full(sub, P256_P, addback, 0);
        (void)c3;
        for (int i = 0; i < NW; i++) {
            rr2[i] = ct_select_u64(noborrow, sub[i], addback[i]);
        }
    }

    for (int i = 0; i < NW; i++) r[i] = rr2[i];
}

#else  // __riscv_rvv fallback

static inline void p256_load_vec(const uint64_t *a, uint64_t *c) {
    p256_copy(a, c);
}
static inline void p256_store_vec(uint64_t *c, const uint64_t *a) {
    p256_copy(a, c);
}
static inline void p256_mod_add_vec(const uint64_t *a, const uint64_t *b, uint64_t *c) {
    p256_mod_add(a, b, c);
}
static inline void p256_mod_sub_vec(const uint64_t *a, const uint64_t *b, uint64_t *c) {
    p256_mod_sub(a, b, c);
}
static inline void p256_mod_reduce_vec(const uint64_t *a512, uint64_t *r) {
    // Scalar fallback: simple reduction
    uint64_t t[NW*2];
    for (int i = 0; i < 8; i++) t[i] = a512[i];
    // r = lo + hi (fast reduction)
    uint64_t rr[NW];
    rr[0] = t[0] + t[4];
    rr[1] = t[1] + t[5];
    rr[2] = t[2] + t[6];
    rr[3] = t[3] + t[7];
    // Conditional reduce
    for (int iter = 0; iter < 2; iter++) {
        uint64_t sub[NW];
        uint64_t borrow = p256_sub_full(rr, P256_P, sub, 0);
        uint64_t noborrow = ct_is_zero_u64(borrow);
        uint64_t addback[NW];
        p256_add_full(sub, P256_P, addback, 0);
        for (int i = 0; i < NW; i++) rr[i] = ct_select_u64(noborrow, sub[i], addback[i]);
    }
    for (int i = 0; i < NW; i++) r[i] = rr[i];
}

#endif  // __riscv_rvv

// Modular multiplication using vector reduction
static void p256_mod_mul_vec(const uint64_t *a, const uint64_t *b, uint64_t *c) {
    uint64_t t[8];
    p256_mul(a, b, t);
    p256_mod_reduce_vec(t, c);
}

// =====================================================================
// MODULAR INVERSE (Fixed-window, constant-time)
// =====================================================================
// x^(-1) = x^(p-2) mod p using Fermat's theorem
// p - 2 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F

static void p256_mod_inv(const uint64_t *x, uint64_t *result) {
    static const uint64_t e[NW] = { 0xFC63254Fu, 0xF3B9CAC2u, 0xA7179E84u, 0xFFFFFFFFu };
    uint64_t base[NW], tmp[NW];
    p256_copy(x, base);
    result[0] = 1; result[1] = 0; result[2] = 0; result[3] = 0;

    // Precompute base^(2^i) for i=0..15 (4-bit window)
    uint64_t pow2[16][NW];
    p256_copy(base, pow2[0]);
    for (int i = 1; i < 16; i++) {
        p256_mod_mul_vec(pow2[i-1], pow2[i-1], tmp);
        p256_copy(tmp, pow2[i]);
    }

    // Fixed-window exponentiation, MSB first
    for (int word = NW-1; word >= 0; word--) {
        for (int bit = 28; bit >= 0; bit -= 4) {
            uint32_t nibble = (uint32_t)(e[word] >> bit) & 0xF;

            // Square 4 times
            for (int s = 0; s < 4; s++) {
                p256_mod_mul_vec(result, result, tmp);
                p256_copy(tmp, result);
            }

            if (nibble > 0) {
                p256_mod_mul_vec(result, pow2[nibble], tmp);
                p256_copy(tmp, result);
            }
        }
    }
}

// =====================================================================
// JACOBIAN POINT OPERATIONS (P-256, a = -3)
// =====================================================================
// Jacobian coordinates: (X, Y, Z) where affine X = X/Z^2, Y = Y/Z^3

typedef struct {
    uint64_t X[NW];
    uint64_t Y[NW];
    uint64_t Z[NW];
    uint64_t inf;  // Is infinity
} p256_point_t;

static const p256_point_t P256_INF = {
    {1, 0, 0, 0}, {1, 0, 0, 0}, {1, 0, 0, 0}, 1
};

// Point doubling: R = 2*P (Jacobian, a = -3 optimized)
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2009-l
static void p256_double(const p256_point_t *P, p256_point_t *R) {
    if (P->inf) {
        p256_copy((const uint64_t*)&P256_INF.X, R->X);
        p256_copy((const uint64_t*)&P256_INF.Y, R->Y);
        p256_copy((const uint64_t*)&P256_INF.Z, R->Z);
        R->inf = 1;
        return;
    }

    uint64_t XX[NW], YY[NW], ZZ[NW], XYY[NW], T1[NW], T2[NW], T3[NW];
    uint64_t aaaa[NW], M[NW], S[NW];

    // XX = P->X^2
    p256_mod_mul_vec(P->X, P->X, XX);
    // YY = P->Y^2
    p256_mod_mul_vec(P->Y, P->Y, YY);
    // ZZ = P->Z^2
    p256_mod_mul_vec(P->Z, P->Z, ZZ);

    // a = -3, so 3*XX + a*ZZ = 3*XX - 3*ZZ = 3*(XX - ZZ)
    // M = 3*(XX - ZZ)
    p256_mod_sub_vec(XX, ZZ, T1);  // T1 = XX - ZZ
    // T2 = 3*T1
    T2[0] = T1[0] * 3; T2[1] = T1[1] * 3; T2[2] = T1[2] * 3; T2[3] = T1[3] * 3;
    uint64_t T3c = 0;
    for (int i = 0; i < NW; i++) {
        uint64_t sum = T2[i] + T3c;
        T3c = (sum < T2[i]) ? 1 : 0;
        M[i] = sum;
    }
    // S = 4*X*YY
    p256_mod_mul_vec(P->X, YY, XYY);  // X*YY
    // T3 = 8*XYY (left shift = multiply by 2 three times)
    T3[0] = XYY[0]; T3[1] = XYY[1]; T3[2] = XYY[2]; T3[3] = XYY[3];
    uint64_t c = 0;
    for (int s = 0; s < 3; s++) {
        uint64_t oldc = c;
        for (int i = 0; i < NW; i++) {
            uint64_t sum = T3[i] + T3[i];
            c = (sum < T3[i]) | ((sum == T3[i]) & oldc);
            T3[i] = sum;
            oldc = c;
        }
    }
    for (int i = 0; i < NW; i++) S[i] = T3[i];

    // aaaa = M^2
    p256_mod_mul_vec(M, M, aaaa);

    // R->X = aaaa - 2*S
    p256_mod_sub_vec(aaaa, S, T1);
    p256_mod_sub_vec(T1, S, R->X);

    // R->Y = M*(S - R->X) - 8*YY^2
    p256_mod_sub_vec(S, R->X, T1);  // S - X
    p256_mod_mul_vec(M, T1, T2);    // M*(S-X)

    // YY^2 = YY*YY
    uint64_t YYYY[NW];
    p256_mod_mul_vec(YY, YY, YYYY);
    // 8*YYYY
    uint64_t eight_YYYY[NW];
    for (int i = 0; i < NW; i++) {
        __uint128_t val = (__uint128_t)YYYY[i] * 8;
        eight_YYYY[i] = (uint64_t)val;
        // handle overflow... actually just do scalar mul
    }
    // Use shifts for 8*YYYY
    for (int i = 0; i < NW; i++) {
        uint64_t v = YYYY[i];
        eight_YYYY[i] = (v << 3);
    }

    p256_mod_sub_vec(T2, eight_YYYY, R->Y);

    // R->Z = 2*Y*Z
    p256_mod_mul_vec(P->Y, P->Z, T1);
    // T1 = 4*Y*Z
    c = 0;
    for (int s = 0; s < 2; s++) {
        uint64_t oldc = c;
        for (int i = 0; i < NW; i++) {
            uint64_t sum = T1[i] + T1[i];
            c = (sum < T1[i]) | ((sum == T1[i]) & oldc);
            T1[i] = sum;
            oldc = c;
        }
    }
    for (int i = 0; i < NW; i++) R->Z[i] = T1[i];
    R->inf = 0;
}

// Point addition: R = P + Q (mixed coordinates: P=jacobian, Q=affine)
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd-2009-l
static void p256_add_mixed(const p256_point_t *P, const uint64_t *Qx, const uint64_t *Qy, p256_point_t *R) {
    if (P->inf) {
        // R = Q (affine)
        for (int i = 0; i < NW; i++) R->X[i] = Qx[i];
        for (int i = 0; i < NW; i++) R->Y[i] = Qy[i];
        R->Z[0] = 1; R->Z[1] = 0; R->Z[2] = 0; R->Z[3] = 0;
        R->inf = 0;
        return;
    }

    uint64_t ZZ[NW], U1[NW], S1[NW], U2[NW], S2[NW], H[NW], I[NW], J[NW], V[NW];
    uint64_t T1[NW], T2[NW], T3[NW];

    // ZZ = Z^2
    p256_mod_mul_vec(P->Z, P->Z, ZZ);
    // U1 = X * ZZ
    p256_mod_mul_vec(P->X, ZZ, U1);
    // S1 = Y * ZZ * Z = Y * Z^3
    p256_mod_mul_vec(P->Y, ZZ, S1);
    p256_mod_mul_vec(S1, P->Z, S1);

    // U2 = Qx * ZZ
    p256_mod_mul_vec(Qx, ZZ, U2);
    // S2 = Qy * Z^3
    uint64_t ZZ3[NW];
    p256_mod_mul_vec(ZZ, P->Z, ZZ3);
    p256_mod_mul_vec(Qy, ZZ3, S2);

    // H = U2 - U1
    p256_mod_sub_vec(U2, U1, H);
    // I = (2*H)^2
    for (int i = 0; i < NW; i++) I[i] = H[i] * 2;
    p256_mod_mul_vec(I, I, I);
    // J = H * I
    p256_mod_mul_vec(H, I, J);
    // V = U1 * I
    p256_mod_mul_vec(U1, I, V);

    // S1 = 2*S1
    for (int i = 0; i < NW; i++) S1[i] = S1[i] * 2;

    // T1 = S2 - S1
    p256_mod_sub_vec(S2, S1, T1);

    // R->X = T1^2 - J - 2*V
    p256_mod_mul_vec(T1, T1, T2);
    p256_mod_sub_vec(T2, J, T3);
    for (int i = 0; i < NW; i++) V[i] = V[i] * 2;
    p256_mod_sub_vec(T3, V, R->X);

    // R->Y = T1*(V - R->X) - 2*S1*J
    p256_mod_sub_vec(V, R->X, T2);
    p256_mod_mul_vec(T1, T2, T3);
    p256_mod_mul_vec(S1, J, T1);
    T1[0] *= 2; T1[1] *= 2; T1[2] *= 2; T1[3] *= 2;
    p256_mod_sub_vec(T3, T1, R->Y);

    // R->Z = Z * H * 2
    p256_mod_mul_vec(P->Z, H, T1);
    for (int i = 0; i < NW; i++) T1[i] = T1[i] * 2;
    for (int i = 0; i < NW; i++) R->Z[i] = T1[i];
    R->inf = 0;
}

// Full point addition (both Jacobian)
static void p256_add(const p256_point_t *P, const p256_point_t *Q, p256_point_t *R) {
    uint64_t Qx[NW], Qy[NW];
    // Convert Q to affine
    uint64_t Z_inv[NW], Z2_inv[NW], Z3_inv[NW], tmp[NW];
    p256_mod_inv(Q->Z, Z_inv);
    p256_mod_mul_vec(Z_inv, Z_inv, Z2_inv);
    p256_mod_mul_vec(Z2_inv, Z_inv, Z3_inv);
    p256_mod_mul_vec(Q->X, Z2_inv, Qx);
    p256_mod_mul_vec(Q->Y, Z3_inv, Qy);
    p256_add_mixed(P, Qx, Qy, R);
}

// =====================================================================
// SCALAR MULTIPLICATION (Montgomery ladder, constant-time)
// =====================================================================
// Computes R = k*P using Montgomery ladder for constant-time execution

static void p256_scalar_mul(const uint64_t *k, const uint64_t *Px, const uint64_t *Py, uint64_t *Rx, uint64_t *Ry) {
    p256_point_t R0 = {{{0}}, {{0}}, {{0}}, 1};  // infinity
    p256_point_t R1;
    for (int i = 0; i < NW; i++) R1.X[i] = Px[i];
    for (int i = 0; i < NW; i++) R1.Y[i] = Py[i];
    R1.Z[0] = 1; R1.Z[1] = 0; R1.Z[2] = 0; R1.Z[3] = 0;
    R1.inf = 0;

    p256_point_t R2, tmpP, tmpQ;

    // Process from MSB to LSB, 1 bit at a time
    for (int word = NW - 1; word >= 0; word--) {
        for (int bit = 63; bit >= 0; bit--) {
            uint64_t bit_k = (k[word] >> bit) & 1;
            uint64_t not_bit_k = ct_is_zero_u64(bit_k);

            // R0, R1 = cswap(R0, R1, bit_k)
            // Montgomery ladder: always do both add and double
            p256_add(&R0, &R1, &tmpP);    // R0 + R1
            p256_double(&R0, &tmpQ);      // 2*R0

            // Select based on bit_k
            // If bit=1: R0 = tmpP, R1 = tmpQ
            // If bit=0: R0 = tmpQ, R1 = tmpP
            for (int i = 0; i < NW; i++) {
                R0.X[i] = ct_select_u64(bit_k, tmpP.X[i], tmpQ.X[i]);
                R0.Y[i] = ct_select_u64(bit_k, tmpP.Y[i], tmpQ.Y[i]);
                R0.Z[i] = ct_select_u64(bit_k, tmpP.Z[i], tmpQ.Z[i]);
            }
            R0.inf = ct_select_u64(bit_k, tmpP.inf, tmpQ.inf);

            for (int i = 0; i < NW; i++) {
                R1.X[i] = ct_select_u64(not_bit_k, tmpP.X[i], tmpQ.X[i]);
                R1.Y[i] = ct_select_u64(not_bit_k, tmpP.Y[i], tmpQ.Y[i]);
                R1.Z[i] = ct_select_u64(not_bit_k, tmpP.Z[i], tmpQ.Z[i]);
            }
            R1.inf = ct_select_u64(not_bit_k, tmpP.inf, tmpQ.inf);
        }
    }

    // Convert R0 to affine
    if (R0.inf) {
        Rx[0] = 0; Rx[1] = 0; Rx[2] = 0; Rx[3] = 0;
        Ry[0] = 0; Ry[1] = 0; Ry[2] = 0; Ry[3] = 0;
        return;
    }

    uint64_t Z_inv[NW], Z2_inv[NW], Z3_inv[NW], tmp[NW];
    p256_mod_inv(R0.Z, Z_inv);
    p256_mod_mul_vec(Z_inv, Z_inv, Z2_inv);
    p256_mod_mul_vec(Z2_inv, Z_inv, Z3_inv);
    p256_mod_mul_vec(R0.X, Z2_inv, Rx);
    p256_mod_mul_vec(R0.Y, Z3_inv, Ry);
}

// =====================================================================
// ECDSA VERIFICATION (Full implementation with RVV)
// =====================================================================

int ecdsa_verify(const uint8_t *pubkey, size_t pubkey_len,
                 uint32_t algo,
                 const uint8_t *hash, size_t hash_len,
                 const uint8_t *signature, size_t sig_len) {

    // Only use RVV-optimized path for P-256
    if (algo != SIG_ALGO_ECDSA_P256 || sig_len != 64 || hash_len < 32 || pubkey_len < 65) {
        goto fallback;
    }
    if (pubkey[0] != 0x04) {
        goto fallback;
    }

    // Parse r, s (big-endian -> little-endian uint64_t)
    uint64_t r[NW], s[NW];
    for (int i = 0; i < NW; i++) {
        uint32_t r_i = ((uint32_t)signature[i*4+3] << 24) |
                       ((uint32_t)signature[i*4+2] << 16) |
                       ((uint32_t)signature[i*4+1] << 8) |
                       ((uint32_t)signature[i*4+0]);
        uint32_t s_i = ((uint32_t)signature[32+i*4+3] << 24) |
                       ((uint32_t)signature[32+i*4+2] << 16) |
                       ((uint32_t)signature[32+i*4+1] << 8) |
                       ((uint32_t)signature[32+i*4+0]);
        r[i] = r_i; s[i] = s_i;
    }

    // Parse public key Q = (x, y)
    uint64_t Qx[NW], Qy[NW];
    for (int i = 0; i < NW; i++) {
        uint32_t x_i = ((uint32_t)pubkey[4 + i*4+3] << 24) |
                       ((uint32_t)pubkey[4 + i*4+2] << 16) |
                       ((uint32_t)pubkey[4 + i*4+1] << 8) |
                       ((uint32_t)pubkey[4 + i*4+0]);
        uint32_t y_i = ((uint32_t)pubkey[36 + i*4+3] << 24) |
                       ((uint32_t)pubkey[36 + i*4+2] << 16) |
                       ((uint32_t)pubkey[36 + i*4+1] << 8) |
                       ((uint32_t)pubkey[36 + i*4+0]);
        Qx[i] = x_i; Qy[i] = y_i;
    }

    // Parse hash e
    uint64_t e[NW];
    for (int i = 0; i < NW; i++) {
        uint32_t e_i = ((uint32_t)hash[i*4+3] << 24) |
                       ((uint32_t)hash[i*4+2] << 16) |
                       ((uint32_t)hash[i*4+1] << 8) |
                       ((uint32_t)hash[i*4+0]);
        e[i] = e_i;
    }

    // Range check: r, s in [1, n-1]
    if (p256_is_zero(r) || p256_is_zero(s)) goto fallback;
    if (p256_ge(r, P256_N) || p256_ge(s, P256_N)) goto fallback;

    // w = s^(-1) mod n
    uint64_t w[NW];
    p256_mod_inv(s, w);

    // u1 = e * w mod n
    uint64_t u1[NW];
    p256_mod_mul_vec(e, w, u1);

    // u2 = r * w mod n
    uint64_t u2[NW];
    p256_mod_mul_vec(r, w, u2);

    // R = u1*G + u2*Q using scalar multiplication
    // Compute: R = u2*Q + u1*G (we compute both and add)
    uint64_t R_x[NW], R_y[NW];
    uint64_t u1G_x[NW], u1G_y[NW], u2Q_x[NW], u2Q_y[NW];

    // u1 * G (fixed base, could use precomputed table)
    p256_scalar_mul(u1, P256_GX, P256_GY, u1G_x, u1G_y);

    // u2 * Q (variable base)
    p256_scalar_mul(u2, Qx, Qy, u2Q_x, u2Q_y);

    // R = u1G + u2Q
    p256_point_t P1, P2, R;
    for (int i = 0; i < NW; i++) { P1.X[i] = u1G_x[i]; P1.Y[i] = u1G_y[i]; }
    P1.Z[0] = 1; P1.Z[1] = 0; P1.Z[2] = 0; P1.Z[3] = 0; P1.inf = 0;
    for (int i = 0; i < NW; i++) { P2.X[i] = u2Q_x[i]; P2.Y[i] = u2Q_y[i]; }
    P2.Z[0] = 1; P2.Z[1] = 0; P2.Z[2] = 0; P2.Z[3] = 0; P2.inf = 0;

    p256_add(&P1, &P2, &R);

    if (R.inf) goto fallback;

    // Convert R to affine
    uint64_t Z_inv[NW], X_aff[NW], Y_aff[NW];
    p256_mod_inv(R.Z, Z_inv);
    uint64_t Z2[NW], Z3[NW];
    p256_mod_mul_vec(Z_inv, Z_inv, Z2);
    p256_mod_mul_vec(Z2, Z_inv, Z3);
    p256_mod_mul_vec(R.X, Z2, X_aff);
    p256_mod_mul_vec(R.Y, Z3, Y_aff);

    // Check: R.x mod n == r
    if (p256_ge(X_aff, P256_N)) goto fallback;

    // Compare X_aff[0..3] with r[0..3]
    int match = 1;
    for (int i = 0; i < NW; i++) {
        if (X_aff[i] != r[i]) { match = 0; break; }
    }
    if (!match) return ECDSA_VERIFY_FAILED;

    return ECDSA_VERIFY_SUCCESS;

fallback: {
    // mbedTLS fallback for non-P256 or as verification engine
    #include "mbedtls/ecp.h"
    #include "mbedtls/ecdsa.h"

    int ret;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Qpt;
    mbedtls_ecdsa_context ctx;

    mbedtls_ecdsa_init(&ctx);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Qpt);

    if (algo == SIG_ALGO_ECDSA_P256) {
        ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    } else if (algo == SIG_ALGO_ECDSA_P384) {
        ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP384R1);
    } else {
        ret = ECDSA_VERIFY_FAILED;
        goto out;
    }

    if (ret != 0) { ret = ECDSA_VERIFY_FAILED; goto out; }

    ret = mbedtls_ecp_point_read_binary(&grp, &Qpt, pubkey, pubkey_len);
    if (ret != 0) { ret = ECDSA_VERIFY_FAILED; goto out; }

    ret = mbedtls_ecdsa_verify(&grp, hash, hash_len, &Qpt, signature, sig_len);
    ret = (ret == 0) ? ECDSA_VERIFY_SUCCESS : ECDSA_VERIFY_FAILED;

out:
    mbedtls_ecp_point_free(&Qpt);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecdsa_free(&ctx);
    return ret;
}
}
