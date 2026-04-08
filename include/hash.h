#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

#define HASH_MAX_DIGEST_SIZE 48  // SHA-384 is 48 bytes

// hash_context_t - opaque hash context
// When __riscv_zk is defined, uses K extension intrinsics
// Otherwise uses mbedTLS
typedef struct {
    uint32_t algo;                    // Hash algorithm
    uint64_t total_len;               // Total message length
    union {
#ifdef __riscv_zk
        uint8_t state[256];           // K extension: up to 256 bytes for SHA-512 state
#else
        void *md_ctx;                  // mbedTLS: md context
        void *md_info;                 // mbedTLS: md info
#endif
    };
} hash_context_t;

int hash_init(hash_context_t *ctx, uint32_t algo);
int hash_update(hash_context_t *ctx, const uint8_t *data, size_t len);
int hash_final(hash_context_t *ctx, uint8_t *digest, size_t *digest_len);
void hash_free(hash_context_t *ctx);

#endif // HASH_H
