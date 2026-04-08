#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

#define HASH_MAX_DIGEST_SIZE 48  // SHA-384 is 48 bytes

typedef struct {
    uint32_t algo;
    void *ctx;  // Opaque mbedTLS context
} hash_context_t;

int hash_init(hash_context_t *ctx, uint32_t algo);
int hash_update(hash_context_t *ctx, const uint8_t *data, size_t len);
int hash_final(hash_context_t *ctx, uint8_t *digest, size_t *digest_len);
void hash_free(hash_context_t *ctx);

#endif // HASH_H
