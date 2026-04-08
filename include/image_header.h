#ifndef IMAGE_HEADER_H
#define IMAGE_HEADER_H

#include <stdint.h>

#define IMAGE_HEADER_SIZE 32

#define HASH_ALGO_SHA256 0
#define HASH_ALGO_SHA384 1

#define SIG_ALGO_ECDSA_P256 0
#define SIG_ALGO_ECDSA_P384 1

typedef struct {
    uint32_t version;        // Image version (e.g., 0x00010000 = 1.0.0)
    uint32_t image_type;     // Image type identifier
    uint32_t image_length;   // Image data length (excluding header and signature)
    uint32_t flags;         // Flags
    uint64_t timestamp;      // Build timestamp
    uint32_t hash_algo;     // Hash algorithm (0=SHA256, 1=SHA384)
    uint32_t sig_algo;      // Signature algorithm (0=ECDSA_P256, 1=ECDSA_P384)
    uint32_t reserved[0];    // Reserved fields (flexible array for future use)
} image_header_t;

_Static_assert(sizeof(image_header_t) == IMAGE_HEADER_SIZE,
               "image_header_t must be exactly 32 bytes");

#endif // IMAGE_HEADER_H
