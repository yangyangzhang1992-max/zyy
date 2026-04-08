# Secure Boot Image Verification Design

## Overview

A modular C implementation for RISC-V secure boot image verification using ECDSA signatures, designed to run on embedded systems with RISC-V K extension support.

## Architecture

```
secure_boot/
├── include/
│   ├── image_header.h      # Header structure and constants
│   ├── hash.h              # Hash interface
│   ├── ecdsa.h             # ECDSA interface
│   └── verify.h            # Main verification interface
├── src/
│   ├── hash.c              # Hash implementation (SHA-256/SHA-384)
│   ├── ecdsa.c             # ECDSA verification via mbedTLS
│   ├── verify.c            # Main verification entry point
│   └── image_tool.c        # Image packaging utility
├── keys/
│   └── ecdsa_pubkey.h      # Embedded ECDSA public key
├── thirdparty/
│   └── mbedtls/            # mbedTLS library (subset)
├── Makefile
└── README.md
```

## Image Format

### Header Structure (32 bytes)

```c
typedef struct {
    uint32_t version;        // Image version (e.g., 0x00010000 = 1.0.0)
    uint32_t image_type;     // Image type identifier
    uint32_t image_length;   // Image data length (excluding header and signature)
    uint32_t flags;          // Flags
    uint64_t timestamp;      // Build timestamp
    uint32_t hash_algo;      // Hash algorithm (0=SHA256, 1=SHA384)
    uint32_t sig_algo;       // Signature algorithm (0=ECDSA_P256, 1=ECDSA_P384)
    uint32_t reserved[5];     // Reserved fields
} image_header_t;
```

### Complete Image Layout

```
[Header (32 bytes)][Image Data][Signature (64 or 96 bytes)]
```

- **Hash computation**: `hash(header || image_data)`
- **Signature**: ECDSA signature over the hash

## Module Specifications

### 1. Hash Module (hash.h/hash.c)

Provides generic hash interface supporting SHA-256 and SHA-384.

**Interface:**
```c
int hash_init(hash_context_t *ctx, uint32_t algo);
int hash_update(hash_context_t *ctx, const uint8_t *data, size_t len);
int hash_final(hash_context_t *ctx, uint8_t *digest, size_t *digest_len);
```

### 2. ECDSA Module (ecdsa.h/ecdsa.c)

Wrapper around mbedTLS for ECDSA signature verification.

**Interface:**
```c
int ecdsa_verify(const uint8_t *pubkey, size_t pubkey_len,
                 const uint8_t *hash, size_t hash_len,
                 const uint8_t *signature, size_t sig_len);
```

**Supported curves:**
- P-256 (256-bit)
- P-384 (384-bit)

### 3. Verify Module (verify.h/verify.c)

Main entry point for image verification.

**Interface:**
```c
int verify_image(const uint8_t *image, size_t image_len);
```

**Return values:**
- `0`: Verification success
- `-1`: Invalid image length
- `-2`: Invalid header fields
- `-3`: Hash computation failure
- `-4`: Signature verification failure

### 4. Public Key Management (ecdsa_pubkey.h)

Embedded ECDSA public key for verification.

```c
extern const uint8_t ecdsa_public_key[];
extern const size_t ecdsa_public_key_len;
```

## Build Configuration

- **Target**: RISC-V with or without K extension (hash operations use software fallback)
- **Compiler**: GCC/Clang for RISC-V
- **mbedTLS**: Minimal subset for ECDSA P-256/P-384 verification

## File Structure

| File | Description |
|------|-------------|
| `image_header.h` | Header structure definition and constants |
| `hash.h/c` | SHA-256/SHA-384 hash implementation |
| `ecdsa.h/c` | mbedTLS ECDSA verification wrapper |
| `verify.h/c` | Image verification entry point |
| `ecdsa_pubkey.h` | Embedded public key |
| `image_tool.c` | Utility to create signed images |
| `Makefile` | Build configuration |

## Usage

### Verifying an Image

```c
#include "verify.h"

int result = verify_image(image_buffer, image_length);
if (result == 0) {
    // Image is authentic
} else {
    // Verification failed
}
```

### Creating a Signed Image (using image_tool)

```bash
./image_tool create --image kernel.bin --key private.pem --output signed.bin
```
