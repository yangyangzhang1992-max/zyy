#include "hash.h"
#include <stdlib.h>
#include <string.h>

#ifdef __riscv_zk

// Use RISC-V K extension intrinsics
#include "riscv-crypto-intrinsics.h"

// SHA-256 constants
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SHA256_LOAD32_BE(X, A, I) do { \
    X = ((uint32_t*)(A))[(I)];         \
    X = __builtin_bswap32(X);           \
} while(0)

#define SHA256_STORE32_BE(X, A, I) do { \
    ((uint32_t*)(A))[(I)] = __builtin_bswap32(X); \
} while(0)

#define CH(X,Y,Z)  ((X&Y)^(~X&Z))
#define MAJ(X,Y,Z) ((X&Y)^(X&Z)^(Y&Z))

#define SUM_0(X)   (_sha256sum0(X))
#define SUM_1(X)   (_sha256sum1(X))
#define SIGMA_0(X) (_sha256sig0(X))
#define SIGMA_1(X) (_sha256sig1(X))

#define ROUND(A,B,C,D,E,F,G,H,K,W) do { \
    H = H + SUM_1(E) + CH(E,F,G) + K + W;   \
    D = D + H;                              \
    H = H + SUM_0(A) + MAJ(A,B,C);         \
} while(0)

#define SCHEDULE(M0,M1,M9,ME) do { \
    M0 = SIGMA_1(ME) + M9 + SIGMA_0(M1) + M0; \
} while(0)

typedef struct {
    uint32_t H[8];          // Hash state
    uint32_t buffer[16];    // Message block buffer
    size_t msg_len;         // Total message length
    size_t buf_len;         // Bytes in buffer
} sha256_context_t;

typedef struct {
    uint64_t H[8];          // Hash state (SHA-512 uses 64-bit words)
    uint8_t buffer[128];     // Message block buffer
    size_t msg_len;         // Total message length
    size_t buf_len;         // Bytes in buffer
} sha512_context_t;

static void sha256_hash_block(uint32_t H[8], uint32_t M[16]) {
    uint32_t a,b,c,d,e,f,g,h;
    uint32_t m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, ma, mb, mc, md, me, mf;
    uint32_t *kp = (uint32_t*)K256;

    a = H[0]; b = H[1]; c = H[2]; d = H[3];
    e = H[4]; f = H[5]; g = H[6]; h = H[7];

    SHA256_LOAD32_BE(m0, M, 0);  SHA256_LOAD32_BE(m1, M, 1);
    SHA256_LOAD32_BE(m2, M, 2);  SHA256_LOAD32_BE(m3, M, 3);
    SHA256_LOAD32_BE(m4, M, 4);  SHA256_LOAD32_BE(m5, M, 5);
    SHA256_LOAD32_BE(m6, M, 6);  SHA256_LOAD32_BE(m7, M, 7);
    SHA256_LOAD32_BE(m8, M, 8);  SHA256_LOAD32_BE(m9, M, 9);
    SHA256_LOAD32_BE(ma, M, 10); SHA256_LOAD32_BE(mb, M, 11);
    SHA256_LOAD32_BE(mc, M, 12); SHA256_LOAD32_BE(md, M, 13);
    SHA256_LOAD32_BE(me, M, 14); SHA256_LOAD32_BE(mf, M, 15);

    uint32_t *ke = kp + 48;

    while(1) {
        ROUND(a, b, c, d, e, f, g, h, kp[ 0], m0)  ROUND(h, a, b, c, d, e, f, g, kp[ 1], m1)
        ROUND(g, h, a, b, c, d, e, f, kp[ 2], m2)  ROUND(f, g, h, a, b, c, d, e, kp[ 3], m3)
        ROUND(e, f, g, h, a, b, c, d, kp[ 4], m4)  ROUND(d, e, f, g, h, a, b, c, kp[ 5], m5)
        ROUND(c, d, e, f, g, h, a, b, kp[ 6], m6)  ROUND(b, c, d, e, f, g, h, a, kp[ 7], m7)
        ROUND(a, b, c, d, e, f, g, h, kp[ 8], m8)  ROUND(h, a, b, c, d, e, f, g, kp[ 9], m9)
        ROUND(g, h, a, b, c, d, e, f, kp[10], ma)  ROUND(f, g, h, a, b, c, d, e, kp[11], mb)
        ROUND(e, f, g, h, a, b, c, d, kp[12], mc)  ROUND(d, e, f, g, h, a, b, c, kp[13], md)
        ROUND(c, d, e, f, g, h, a, b, kp[14], me)  ROUND(b, c, d, e, f, g, h, a, kp[15], mf)

        if(kp == ke) break;
        kp += 16;

        SCHEDULE(m0, m1, m9, me)  SCHEDULE(m1, m2, ma, mf)
        SCHEDULE(m2, m3, mb, m0)  SCHEDULE(m3, m4, mc, m1)
        SCHEDULE(m4, m5, md, m2)  SCHEDULE(m5, m6, me, m3)
        SCHEDULE(m6, m7, mf, m4)  SCHEDULE(m7, m8, m0, m5)
        SCHEDULE(m8, m9, m1, m6)  SCHEDULE(m9, ma, m2, m7)
        SCHEDULE(ma, mb, m3, m8)  SCHEDULE(mb, mc, m4, m9)
        SCHEDULE(mc, md, m5, ma)  SCHEDULE(md, me, m6, mb)
        SCHEDULE(me, mf, m7, mc)  SCHEDULE(mf, m0, m8, md)
    }

    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

// SHA-512 functions using K extension on RV64
#if __riscv_xlen == 64
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2ULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acb5ULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static inline uint64_t _ror64(uint64_t x, int n) { return (x >> n) | (x << (64-n)); }
static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
#define SUM0(x) (_ror64(x, 28) ^ _ror64(x, 34) ^ _ror64(x, 39))
#define SUM1(x) (_ror64(x, 14) ^ _ror64(x, 18) ^ _ror64(x, 41))
#define SIG0(x) (_ror64(x, 1) ^ _ror64(x, 8) ^ (x >> 7))
#define SIG1(x) (_ror64(x, 19) ^ _ror64(x, 61) ^ (x >> 6))

static void sha512_hash_block(uint64_t H[8], uint64_t M[16]) {
    uint64_t a,b,c,d,e,f,g,h;
    uint64_t m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, ma, mb, mc, md, me, mf;
    uint64_t T1, T2;
    uint64_t *kp = (uint64_t*)K512;

    a = H[0]; b = H[1]; c = H[2]; d = H[3];
    e = H[4]; f = H[5]; g = H[6]; h = H[7];

    for (int i = 0; i < 16; i++) {
        m0 = __builtin_bswap64(((uint64_t*)M)[i]);
    }

    for (int i = 0; i < 16; i++) {
        T1 = h + SUM1(e) + Ch(e, f, g) + kp[i] + m0;
        T2 = SUM0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}
#endif  // __riscv_xlen == 64

int hash_init(hash_context_t *ctx, uint32_t algo) {
    ctx->algo = algo;
    ctx->total_len = 0;

    if (algo == HASH_ALGO_SHA256) {
        sha256_context_t *s = (sha256_context_t *)ctx->state;
        s->H[0] = 0x6a09e667; s->H[1] = 0xbb67ae85;
        s->H[2] = 0x3c6ef372; s->H[3] = 0xa54ff53a;
        s->H[4] = 0x510e527f; s->H[5] = 0x9b05688c;
        s->H[6] = 0x1f83d9ab; s->H[7] = 0x5be0cd19;
        s->buf_len = 0;
        return 0;
    }
#if __riscv_xlen == 64
    else if (algo == HASH_ALGO_SHA384) {
        sha512_context_t *s = (sha512_context_t *)ctx->state;
        s->H[0] = 0xcbbb9d5dc1059ed8ULL; s->H[1] = 0x629a292a367cd507ULL;
        s->H[2] = 0x9159015a3070dd17ULL; s->H[3] = 0x152fecd8f70e5939ULL;
        s->H[4] = 0x67332667ffc00b31ULL; s->H[5] = 0x8eb44a8768581511ULL;
        s->H[6] = 0xdb0c2e0d64f98fa7ULL; s->H[7] = 0x47b5481dbefa4fa4ULL;
        s->buf_len = 0;
        return 0;
    }
#endif
    return -1;
}

int hash_update(hash_context_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data) return -1;

    ctx->total_len += len;

    if (ctx->algo == HASH_ALGO_SHA256) {
        sha256_context_t *s = (sha256_context_t *)ctx->state;
        size_t i;
        for (i = 0; i < len; i++) {
            s->buffer[s->buf_len++] = data[i];
            if (s->buf_len == 64) {
                sha256_hash_block(s->H, s->buffer);
                s->buf_len = 0;
            }
        }
        return 0;
    }
#if __riscv_xlen == 64
    else if (ctx->algo == HASH_ALGO_SHA384) {
        sha512_context_t *s = (sha512_context_t *)ctx->state;
        size_t i;
        for (i = 0; i < len; i++) {
            s->buffer[s->buf_len++] = data[i];
            if (s->buf_len == 128) {
                sha512_hash_block(s->H, (uint64_t*)s->buffer);
                s->buf_len = 0;
            }
        }
        return 0;
    }
#endif
    return -1;
}

int hash_final(hash_context_t *ctx, uint8_t *digest, size_t *digest_len) {
    if (!ctx || !digest || !digest_len) return -1;

    if (ctx->algo == HASH_ALGO_SHA256) {
        sha256_context_t *s = (sha256_context_t *)ctx->state;
        uint32_t pad_len = (s->buf_len < 56) ? (56 - s->buf_len) : (120 - s->buf_len);
        uint8_t pad[120];
        pad[0] = 0x80;
        memset(pad + 1, 0, pad_len - 1);
        uint64_t bit_len = ctx->total_len * 8;
        for (int i = 0; i < 8; i++) {
            pad[pad_len++] = (bit_len >> (56 - i * 8)) & 0xff;
        }
        hash_update(ctx, pad, pad_len);
        for (int i = 0; i < 8; i++) {
            digest[i*4+0] = (s->H[i] >> 24) & 0xff;
            digest[i*4+1] = (s->H[i] >> 16) & 0xff;
            digest[i*4+2] = (s->H[i] >> 8) & 0xff;
            digest[i*4+3] = s->H[i] & 0xff;
        }
        *digest_len = 32;
        return 0;
    }
#if __riscv_xlen == 64
    else if (ctx->algo == HASH_ALGO_SHA384) {
        sha512_context_t *s = (sha512_context_t *)ctx->state;
        uint8_t pad[256];
        pad[0] = 0x80;
        size_t pad_len = 1;
        size_t rem = s->buf_len % 128;
        size_t to_pad = (rem < 112) ? (112 - rem) : (240 - rem);
        memset(pad + 1, 0, to_pad);
        pad_len += to_pad;
        uint16_t bit_len_high = (ctx->total_len * 8) >> 64;
        uint16_t bit_len_low = (ctx->total_len * 8) & 0xffffffffffffffffULL;
        for (int i = 0; i < 16; i++) {
            pad[pad_len++] = (bit_len_low >> (112 - i * 8)) & 0xff;
        }
        hash_update(ctx, pad, pad_len);
        for (int i = 0; i < 8; i++) {
            uint64_t x = __builtin_bswap64(s->H[i]);
            memcpy(digest + i * 8, &x, 8);
        }
        *digest_len = 48;
        return 0;
    }
#endif
    return -1;
}

void hash_free(hash_context_t *ctx) {
    if (ctx) {
        memset(ctx->state, 0, sizeof(ctx->state));
    }
}

#else  // __riscv_zk

// Fallback: Use mbedTLS when K extension is not available
#include "mbedtls/md.h"

int hash_init(hash_context_t *ctx, uint32_t algo) {
    ctx->algo = algo;
    ctx->md_info = NULL;
    ctx->md_ctx = calloc(1, sizeof(mbedtls_md_context_t));
    if (!ctx->md_ctx) return -1;
    mbedtls_md_init(ctx->md_ctx);

    const mbedtls_md_info_t *info;
    if (algo == HASH_ALGO_SHA256) {
        info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    } else if (algo == HASH_ALGO_SHA384) {
        info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
    } else {
        free(ctx->md_ctx);
        return -1;
    }
    if (!info) {
        free(ctx->md_ctx);
        return -1;
    }
    if (mbedtls_md_setup(ctx->md_ctx, info, 0) != 0) {
        free(ctx->md_ctx);
        return -1;
    }
    if (mbedtls_md_starts(ctx->md_ctx) != 0) {
        mbedtls_md_free(ctx->md_ctx);
        free(ctx->md_ctx);
        return -1;
    }
    ctx->md_info = info;
    return 0;
}

int hash_update(hash_context_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !ctx->md_ctx) return -1;
    return mbedtls_md_update(ctx->md_ctx, data, len);
}

int hash_final(hash_context_t *ctx, uint8_t *digest, size_t *digest_len) {
    if (!ctx || !ctx->md_ctx || !digest || !digest_len) return -1;
    *digest_len = mbedtls_md_get_size(ctx->md_info);
    return mbedtls_md_finish(ctx->md_ctx, digest);
}

void hash_free(hash_context_t *ctx) {
    if (ctx && ctx->md_ctx) {
        mbedtls_md_free(ctx->md_ctx);
        free(ctx->md_ctx);
        ctx->md_ctx = NULL;
    }
}

#endif  // __riscv_zk
