#include "verify.h"
#include "image_header.h"
#include "hash.h"
#include "ecdsa.h"
#include "../keys/ecdsa_pubkey.h"
#include <string.h>

int verify_image(const uint8_t *image, size_t image_len) {
    int ret;
    const image_header_t *header;
    size_t expected_min_len;
    size_t hash_computed_len;
    size_t sig_len;
    uint8_t hash[HASH_MAX_DIGEST_SIZE];
    size_t hash_len;
    hash_context_t hash_ctx;

    // Check minimum length
    if (image == NULL || image_len < IMAGE_HEADER_SIZE) {
        return VERIFY_ERROR_LENGTH;
    }

    header = (const image_header_t *)image;

    // Validate header fields
    if (header->image_length == 0) {
        return VERIFY_ERROR_HEADER;
    }

    // Calculate expected total length: header + image_data + signature
    if (header->sig_algo == SIG_ALGO_ECDSA_P256) {
        sig_len = 64;  // r(32) + s(32)
    } else if (header->sig_algo == SIG_ALGO_ECDSA_P384) {
        sig_len = 96;  // r(48) + s(48)
    } else {
        return VERIFY_ERROR_HEADER;
    }

    expected_min_len = IMAGE_HEADER_SIZE + header->image_length + sig_len;
    if (image_len < expected_min_len) {
        return VERIFY_ERROR_LENGTH;
    }

    // Initialize hash context
    if (header->hash_algo == HASH_ALGO_SHA256) {
        hash_len = 32;
    } else if (header->hash_algo == HASH_ALGO_SHA384) {
        hash_len = 48;
    } else {
        return VERIFY_ERROR_HEADER;
    }

    ret = hash_init(&hash_ctx, header->hash_algo);
    if (ret != 0) {
        return VERIFY_ERROR_HASH;
    }

    // Hash header + image_data
    ret = hash_update(&hash_ctx, image, IMAGE_HEADER_SIZE);
    if (ret != 0) {
        hash_free(&hash_ctx);
        return VERIFY_ERROR_HASH;
    }

    ret = hash_update(&hash_ctx, image + IMAGE_HEADER_SIZE, header->image_length);
    if (ret != 0) {
        hash_free(&hash_ctx);
        return VERIFY_ERROR_HASH;
    }

    ret = hash_final(&hash_ctx, hash, &hash_computed_len);
    if (ret != 0 || hash_computed_len != hash_len) {
        hash_free(&hash_ctx);
        return VERIFY_ERROR_HASH;
    }
    hash_free(&hash_ctx);

    // Verify signature
    const uint8_t *signature = image + IMAGE_HEADER_SIZE + header->image_length;

    ret = ecdsa_verify(ecdsa_public_key, ecdsa_public_key_len,
                       header->sig_algo,
                       hash, hash_len,
                       signature, sig_len);

    if (ret != ECDSA_VERIFY_SUCCESS) {
        return VERIFY_ERROR_SIGNATURE;
    }

    return VERIFY_SUCCESS;
}
