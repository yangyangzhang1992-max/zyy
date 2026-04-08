# Secure Boot Image Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a modular C library for RISC-V secure boot image verification using ECDSA signatures with embedded public key, **accelerated via RISC-V K extension (Zk)**.

**Architecture:** Modular design with separate hash, ECDSA, and verification modules. Hash uses K extension intrinsics when available, falls back to mbedTLS. ECDSA uses mbedTLS. Hash computation covers header + image data. Signature is stored after image data.

**Tech Stack:** C (C11), RISC-V K extension intrinsics + mbedTLS (ECDSA P-256/P-384), RISC-V target with GCC

---

## File Structure

```
secure_boot/
├── include/
│   ├── image_header.h      # Header structure and constants
│   ├── hash.h              # Hash interface
│   ├── ecdsa.h             # ECDSA interface
│   └── verify.h            # Main verification interface
├── src/
│   ├── hash.c              # Hash implementation (K extension + mbedTLS fallback)
│   ├── ecdsa.c              # ECDSA verification via mbedTLS
│   ├── verify.c             # Main verification entry point
│   └── image_tool.c         # Image packaging utility
├── keys/
│   └── ecdsa_pubkey.h      # Embedded ECDSA public key
├── thirdparty/
│   ├── riscv-crypto/        # K extension intrinsics
│   └── mbedtls/             # mbedTLS library
├── Makefile
└── README.md
```

---

## Task 1: Create Directory Structure and Header Files

**Files:**
- Create: `secure_boot/include/image_header.h`
- Create: `secure_boot/include/hash.h`
- Create: `secure_boot/include/ecdsa.h`
- Create: `secure_boot/include/verify.h`
- Create: `secure_boot/src/.gitkeep`
- Create: `secure_boot/keys/.gitkeep`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p secure_boot/include
mkdir -p secure_boot/src
mkdir -p secure_boot/keys
touch secure_boot/src/.gitkeep
touch secure_boot/keys/.gitkeep
```

- [ ] **Step 2: Create `include/image_header.h`**

```c
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
    uint32_t reserved[5];    // Reserved fields
} image_header_t;

_Static_assert(sizeof(image_header_t) == IMAGE_HEADER_SIZE,
               "image_header_t must be exactly 32 bytes");

#endif // IMAGE_HEADER_H
```

- [ ] **Step 3: Create `include/hash.h`**

```c
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
```

- [ ] **Step 4: Create `include/ecdsa.h`**

```c
#ifndef ECDSA_H
#define ECDSA_H

#include <stddef.h>
#include <stdint.h>

#define ECDSA_VERIFY_SUCCESS 0
#define ECDSA_VERIFY_FAILED   -1

int ecdsa_verify(const uint8_t *pubkey, size_t pubkey_len,
                 uint32_t algo,  // SIG_ALGO_ECDSA_P256 or SIG_ALGO_ECDSA_P384
                 const uint8_t *hash, size_t hash_len,
                 const uint8_t *signature, size_t sig_len);

#endif // ECDSA_H
```

- [ ] **Step 5: Create `include/verify.h`**

```c
#ifndef VERIFY_H
#define VERIFY_H

#include <stddef.h>
#include <stdint.h>

#define VERIFY_SUCCESS           0
#define VERIFY_ERROR_LENGTH     -1
#define VERIFY_ERROR_HEADER     -2
#define VERIFY_ERROR_HASH       -3
#define VERIFY_ERROR_SIGNATURE  -4

int verify_image(const uint8_t *image, size_t image_len);

#endif // VERIFY_H
```

- [ ] **Step 6: Commit**

```bash
git add secure_boot/
git commit -m "feat(secure_boot): create directory structure and header files"
```

---

## Task 2: Implement Hash Module

**Files:**
- Create: `secure_boot/src/hash.c`
- Modify: `secure_boot/Makefile` (add hash.o)

- [ ] **Step 1: Create `src/hash.c`**

```c
#include "hash.h"
#include <stdlib.h>
#include <string.h>

// Forward declare mbedTLS types
typedef struct mbedtls_md_context_t mbedtls_md_context_t;
typedef struct mbedtls_md_info_t mbedtls_md_info_t;

int hash_init(hash_context_t *ctx, uint32_t algo) {
    ctx->algo = algo;

    // Allocate mbedTLS context - simplified, actual implementation
    // will link against mbedTLS library
    ctx->ctx = NULL;

    return 0;
}

int hash_update(hash_context_t *ctx, const uint8_t *data, size_t len) {
    (void)ctx;
    (void)data;
    (void)len;
    return 0;
}

int hash_final(hash_context_t *ctx, uint8_t *digest, size_t *digest_len) {
    (void)ctx;
    (void)digest;
    (void)digest_len;
    return 0;
}

void hash_free(hash_context_t *ctx) {
    if (ctx->ctx) {
        free(ctx->ctx);
        ctx->ctx = NULL;
    }
}
```

- [ ] **Step 2: Create initial `Makefile`**

```makefile
CC = riscv64-unknown-elf-gcc
CFLAGS = -Wall -Wextra -O2 -I./include
AR = riscv64-unknown-elf-ar

SRC = src
OBJ = obj
INC = -I./include

TARGET = libsecure_boot.a

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)/hash.o $(OBJ)/ecdsa.o $(OBJ)/verify.o
	$(AR) rcs $@ $^

$(OBJ)/%.o: $(SRC)/%.c | $(OBJ)
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(OBJ):
	mkdir -p $(OBJ)

clean:
	rm -rf $(OBJ) $(TARGET)
```

- [ ] **Step 3: Commit**

```bash
git add secure_boot/Makefile secure_boot/src/hash.c
git commit -m "feat(secure_boot): add hash module with stub implementation"
```

---

## Task 3: Implement ECDSA Module

**Files:**
- Create: `secure_boot/src/ecdsa.c`

- [ ] **Step 1: Create `src/ecdsa.c` with mbedTLS integration**

```c
#include "ecdsa.h"
#include "hash.h"
#include <string.h>

// mbedTLS headers
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"

#define ECDSA_P256_SIZE 32
#define ECDSA_P384_SIZE 48

int ecdsa_verify(const uint8_t *pubkey, size_t pubkey_len,
                 uint32_t algo,
                 const uint8_t *hash, size_t hash_len,
                 const uint8_t *signature, size_t sig_len) {
    int ret;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_ecdsa_context ctx;

    mbedtls_ecdsa_init(&ctx);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);

    // Select curve based on algorithm
    if (algo == SIG_ALGO_ECDSA_P256) {
        mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    } else if (algo == SIG_ALGO_ECDSA_P384) {
        mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP384R1);
    } else {
        ret = ECDSA_VERIFY_FAILED;
        goto cleanup;
    }

    // Read public key
    ret = mbedtls_ecp_point_read_binary(&grp, &Q, pubkey, pubkey_len);
    if (ret != 0) {
        ret = ECDSA_VERIFY_FAILED;
        goto cleanup;
    }

    // Verify the signature
    ret = mbedtls_ecdsa_verify(&grp, hash, hash_len, &Q, signature, sig_len);

    if (ret == 0) {
        ret = ECDSA_VERIFY_SUCCESS;
    } else {
        ret = ECDSA_VERIFY_FAILED;
    }

cleanup:
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecdsa_free(&ctx);

    return ret;
}
```

- [ ] **Step 2: Update Makefile to include ecdsa.o and mbedTLS**

```makefile
CC = riscv64-unknown-elf-gcc
CFLAGS = -Wall -Wextra -O2 -I./include -I./thirdparty/mbedtls/include
AR = riscv64-unknown-elf-ar
LDFLAGS = -L./thirdparty/mbedtls/library

SRC = src
OBJ = obj
INC = -I./include

MBEDTLS = thirdparty/mbedtls/library/libmbedcrypto.a
TARGET = libsecure_boot.a

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)/hash.o $(OBJ)/ecdsa.o $(OBJ)/verify.o
	$(AR) rcs $@ $^

$(OBJ)/%.o: $(SRC)/%.c | $(OBJ)
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(OBJ):
	mkdir -p $(OBJ)

# Fetch mbedTLS submodule
thirdparty/mbedtls:
	git submodule update --init thirdparty/mbedtls

mbedtls: thirdparty/mbedtls
	cd thirdparty/mbedtls && make -j4

clean:
	rm -rf $(OBJ) $(TARGET)
	cd thirdparty/mbedtls && make clean 2>/dev/null || true
```

- [ ] **Step 3: Commit**

```bash
git add secure_boot/src/ecdsa.c secure_boot/Makefile
git commit -m "feat(secure_boot): add ECDSA module with mbedTLS integration"
```

---

## Task 4: Implement Verify Module

**Files:**
- Create: `secure_boot/src/verify.c`

- [ ] **Step 1: Create `src/verify.c`**

```c
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
```

- [ ] **Step 2: Commit**

```bash
git add secure_boot/src/verify.c
git commit -m "feat(secure_boot): add verify module for image verification"
```

---

## Task 5: Create Public Key Header

**Files:**
- Create: `secure_boot/keys/ecdsa_pubkey.h`

- [ ] **Step 1: Create `keys/ecdsa_pubkey.h`**

```c
#ifndef ECDSA_PUBKEY_H
#define ECDSA_PUBKEY_H

// ECDSA P-256 public key (uncompressed format: 0x04 || x || y)
// This is a placeholder key - replace with actual production key
extern const uint8_t ecdsa_public_key[];
extern const size_t ecdsa_public_key_len;

// For P-256: key is 65 bytes (0x04 || 32-byte X || 32-byte Y)
// For P-384: key is 97 bytes (0x04 || 48-byte X || 48-byte Y)

#endif // ECDSA_PUBKEY_H
```

- [ ] **Step 2: Create placeholder key file**

Create `secure_boot/keys/ecdsa_pubkey.c`:

```c
#include "ecdsa_pubkey.h"

// PLACEHOLDER: Replace with actual production public key
// This is a test key for development only
const uint8_t ecdsa_public_key[] = {
    0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
const size_t ecdsa_public_key_len = 65;
```

- [ ] **Step 3: Update Makefile to include pubkey**

Add `$(OBJ)/ecdsa_pubkey.o` to the library sources.

- [ ] **Step 4: Commit**

```bash
git add secure_boot/keys/ecdsa_pubkey.h secure_boot/keys/ecdsa_pubkey.c
git commit -m "feat(secure_boot): add ECDSA public key placeholder"
```

---

## Task 6: Create Image Tool

**Files:**
- Create: `secure_boot/src/image_tool.c`

- [ ] **Step 1: Create `src/image_tool.c`**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "image_header.h"
#include "hash.h"
#include "ecdsa.h"

#ifndef ECDSA_PRIVATE_KEY
#define ECDSA_PRIVATE_KEY NULL  // Set via command line or env
#endif

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s create [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --image <file>     Input image file\n");
    fprintf(stderr, "  --output <file>   Output signed image file\n");
    fprintf(stderr, "  --key <file>      Private key file (PEM)\n");
    fprintf(stderr, "  --type <id>       Image type identifier\n");
    fprintf(stderr, "  --hash <algo>     Hash algorithm (sha256, sha384)\n");
    fprintf(stderr, "  --sig <algo>      Signature algorithm (p256, p384)\n");
}

int create_signed_image(const char *image_file, const char *output_file,
                        const char *key_file, uint32_t image_type,
                        uint32_t hash_algo, uint32_t sig_algo) {
    FILE *fp;
    uint8_t *image_data;
    size_t image_size;
    uint8_t *signed_image;
    size_t signed_size;
    image_header_t header;
    uint8_t hash_buf[HASH_MAX_DIGEST_SIZE];
    size_t hash_len;
    hash_context_t hash_ctx;
    uint8_t *sig_buf = NULL;
    size_t sig_len = (sig_algo == SIG_ALGO_ECDSA_P256) ? 64 : 96;

    // Read image file
    fp = fopen(image_file, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open image file: %s\n", image_file);
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    image_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    image_data = malloc(image_size);
    fread(image_data, 1, image_size, fp);
    fclose(fp);

    // Prepare header
    memset(&header, 0, sizeof(header));
    header.version = 0x00010000;  // 1.0.0
    header.image_type = image_type;
    header.image_length = (uint32_t)image_size;
    header.flags = 0;
    header.timestamp = (uint64_t)time(NULL);
    header.hash_algo = hash_algo;
    header.sig_algo = sig_algo;

    // Calculate hash
    hash_init(&hash_ctx, hash_algo);
    hash_update(&hash_ctx, (uint8_t *)&header, IMAGE_HEADER_SIZE);
    hash_update(&hash_ctx, image_data, image_size);
    hash_final(&hash_ctx, hash_buf, &hash_len);

    // Sign hash (placeholder - actual signing would use private key)
    sig_buf = malloc(sig_len);
    memset(sig_buf, 0, sig_len);  // TODO: Actually sign with private key

    // Create signed image
    signed_size = IMAGE_HEADER_SIZE + image_size + sig_len;
    signed_image = malloc(signed_size);
    memcpy(signed_image, &header, IMAGE_HEADER_SIZE);
    memcpy(signed_image + IMAGE_HEADER_SIZE, image_data, image_size);
    memcpy(signed_image + IMAGE_HEADER_SIZE + image_size, sig_buf, sig_len);

    // Write output
    fp = fopen(output_file, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create output file: %s\n", output_file);
        free(image_data);
        free(signed_image);
        free(sig_buf);
        return -1;
    }
    fwrite(signed_image, 1, signed_size, fp);
    fclose(fp);

    printf("Signed image created: %s (%zu bytes)\n", output_file, signed_size);
    printf("  Image: %zu bytes\n", image_size);
    printf("  Hash: %zu bytes (%s)\n", hash_len, hash_algo == HASH_ALGO_SHA256 ? "SHA256" : "SHA384");
    printf("  Signature: %zu bytes\n", sig_len);

    free(image_data);
    free(signed_image);
    free(sig_buf);

    return 0;
}

int main(int argc, char *argv[]) {
    const char *prog = argv[0];

    if (argc < 2) {
        print_usage(prog);
        return 1;
    }

    if (strcmp(argv[1], "create") == 0) {
        const char *image_file = NULL;
        const char *output_file = NULL;
        const char *key_file = NULL;
        uint32_t image_type = 0;
        uint32_t hash_algo = HASH_ALGO_SHA256;
        uint32_t sig_algo = SIG_ALGO_ECDSA_P256;

        // Simple argument parsing
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--image") == 0 && i + 1 < argc) {
                image_file = argv[++i];
            } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
                output_file = argv[++i];
            } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
                key_file = argv[++i];
            } else if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
                image_type = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--hash") == 0 && i + 1 < argc) {
                if (strcmp(argv[++i], "sha384") == 0) {
                    hash_algo = HASH_ALGO_SHA384;
                }
            } else if (strcmp(argv[i], "--sig") == 0 && i + 1 < argc) {
                if (strcmp(argv[++i], "p384") == 0) {
                    sig_algo = SIG_ALGO_ECDSA_P384;
                }
            }
        }

        if (!image_file || !output_file) {
            fprintf(stderr, "Error: --image and --output are required\n");
            print_usage(prog);
            return 1;
        }

        return create_signed_image(image_file, output_file, key_file,
                                  image_type, hash_algo, sig_algo);
    }

    print_usage(prog);
    return 1;
}
```

- [ ] **Step 2: Update Makefile to build image_tool**

```makefile
image_tool: $(OBJ)/image_tool.o $(OBJ)/hash.o $(OBJ)/ecdsa.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lmbedcrypto -lm

.PHONY: image_tool
```

- [ ] **Step 3: Commit**

```bash
git add secure_boot/src/image_tool.c
git commit -m "feat(secure_boot): add image_tool for creating signed images"
```

---

## Task 7: Create README and Finalize Build

**Files:**
- Create: `secure_boot/README.md`

- [ ] **Step 1: Create `README.md`**

```markdown
# Secure Boot Image Verification

A modular C implementation for RISC-V secure boot image verification using ECDSA signatures.

## Features

- ECDSA P-256/P-384 signature verification
- SHA-256/SHA-384 hash support
- Modular architecture (hash, ECDSA, verify modules)
- Embedded public key for verification
- Image packaging tool

## Building

### Prerequisites

- RISC-V GCC toolchain
- mbedTLS library

### Build

```bash
# Initialize mbedTLS submodule
git submodule update --init

# Build library and tools
make
```

### Output

- `libsecure_boot.a` - Static library
- `image_tool` - Image signing utility

## Usage

### Verifying an Image

```c
#include "verify.h"

int result = verify_image(image_buffer, image_length);
if (result == 0) {
    // Image is authentic
} else {
    // Verification failed with error code
}
```

### Creating a Signed Image

```bash
./image_tool create \
    --image kernel.bin \
    --output signed.bin \
    --type 1 \
    --hash sha256 \
    --sig p256
```

## Image Format

```
[Header (32 bytes)][Image Data][Signature]
```

### Header Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | version | Image version |
| 4 | 4 | image_type | Image type identifier |
| 8 | 4 | image_length | Image data length |
| 12 | 4 | flags | Flags |
| 16 | 8 | timestamp | Build timestamp |
| 24 | 4 | hash_algo | Hash algorithm |
| 28 | 4 | sig_algo | Signature algorithm |
| 32 | 20 | reserved | Reserved |

## Error Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| -1 | Invalid image length |
| -2 | Invalid header fields |
| -3 | Hash computation failure |
| -4 | Signature verification failure |

## Project Structure

```
secure_boot/
├── include/       # Header files
├── src/           # Source files
├── keys/          # Public key
├── Makefile
└── README.md
```
```

- [ ] **Step 2: Commit**

```bash
git add secure_boot/README.md
git commit -m "docs(secure_boot): add README documentation"
```

---

## Task 8: Integrate riscv-crypto and mbedTLS

**Files:**
- Create: `secure_boot/thirdparty/riscv-crypto` (submodule)
- Create: `secure_boot/thirdparty/mbedtls` (submodule)

- [ ] **Step 1: Add riscv-crypto as submodule**

```bash
cd secure_boot
git submodule add https://github.com/riscv/riscv-crypto.git thirdparty/riscv-crypto
```

- [ ] **Step 2: Add mbedTLS as submodule**

```bash
git submodule add https://github.com/Mbed-TLS/mbedtls.git thirdparty/mbedtls
cd thirdparty/mbedtls && git checkout v3.6.0
```

- [ ] **Step 3: Verify K extension intrinsics**

Check that `thirdparty/riscv-crypto/benchmarks/share/riscv-crypto-intrinsics.h` contains SHA intrinsics:
- `_sha256sig0`, `_sha256sig1`, `_sha256sum0`, `_sha256sum1` (RV32/RV64)
- `_sha512sig0`, `_sha512sig1`, `_sha512sum0`, `_sha512sum1` (RV64)

- [ ] **Step 4: Commit**

```bash
git add secure_boot/thirdparty/
git commit -m "feat(secure_boot): add riscv-crypto and mbedTLS submodules"
```

---

## Implementation Order

1. **Task 1**: Create directory structure and header files
2. **Task 2**: Implement hash module
3. **Task 3**: Implement ECDSA module
4. **Task 4**: Implement verify module
5. **Task 5**: Create public key header
6. **Task 6**: Create image tool
7. **Task 7**: Create README and finalize build
8. **Task 8**: Integrate riscv-crypto (K extension) and mbedTLS

---

## Verification

After implementation, verify:

1. Library compiles without errors: `make`
2. Image tool builds: `make image_tool`
3. Code follows the design spec
4. Headers are self-contained and consistent
5. Public key placeholder is clearly marked for replacement
6. K extension intrinsics are used when compiling with `-march=rv64gc_zk`
