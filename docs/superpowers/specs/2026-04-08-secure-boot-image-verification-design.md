# Secure Boot Image Verification Design

## Overview

A modular C implementation for RISC-V secure boot image verification using ECDSA signatures, with **hardware acceleration via RISC-V K extension (Zk)**.

## Architecture

```
secure_boot/
├── include/
│   ├── image_header.h      # Header structure and constants
│   ├── hash.h              # Hash interface
│   ├── ecdsa.h             # ECDSA interface
│   └── verify.h            # Main verification interface
├── src/
│   ├── hash.c              # Hash implementation (K extension + mbedTLS fallback)
│   ├── ecdsa.c             # ECDSA verification via mbedTLS
│   ├── verify.c            # Main verification entry point
│   └── image_tool.c        # Image packaging utility
├── keys/
│   └── ecdsa_pubkey.h      # Embedded ECDSA public key
├── thirdparty/
│   ├── riscv-crypto/       # K extension intrinsics
│   └── mbedtls/            # mbedTLS library for ECDSA
├── Makefile
└── README.md
```

## RISC-V K Extension (Zk) Acceleration

**K extension (Zk) does NOT include ECDSA point multiplication.** It provides:

| Component | K Extension Support | Implementation |
|-----------|--------------------|----------------|
| SHA-256 hash | ✅ Yes | `_sha256sig0/sum0` intrinsics |
| SHA-512 hash | ✅ Yes | `_sha512sig0/sum0` intrinsics |
| AES | ✅ Yes | AES-NI equivalent |
| ECDSA verification | ❌ No | Software (mbedTLS) |

### K Extension Composition

**Zk** = Zkn + Zkr + Zkt

| Subset | Contents |
|--------|----------|
| **Zkn** (NIST Suite) | AES (zkne/zknd), SHA-2 (zknh), SM3/SM4, bitmanip (zbkb) |
| **Zkr** | Entropy source for TRNG |
| **Zkt** | Data-independent execution latency (constant-time) |

**Note:** There is no RISC-V extension for EC arithmetic. ECDSA point multiplication must be implemented in software using big-integer operations.

### SHA-256 Intrinsics (K extension)
```c
_sha256sig0(rs1)   // σigma0: ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3)
_sha256sig1(rs1)   // σigma1: ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10)
_sha256sum0(rs1)   // Σigma0: ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22)
_sha256sum1(rs1)   // Σigma1: ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25)
```

### SHA-512 Intrinsics (RV64 only)
```c
_sha512sig0(rs1)   // σigma0: ROTR(x,1) ^ ROTR(x,8) ^ SHR(x,7)
_sha512sig1(rs1)   // σigma1: ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6)
_sha512sum0(rs1)   // Σigma0: ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39)
_sha512sum1(rs1)   // Σigma1: ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41)
```

### Fallback
Without K extension (`__riscv_zk` not defined), hash operations use mbedTLS software implementation.

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

- **Hash computation**: `hash(header || image_data)` using K extension intrinsics
- **Signature**: ECDSA P-256/P-384 signature over hash (via mbedTLS)

## Module Specifications

### 1. Hash Module (hash.h/hash.c)

Provides hash interface supporting SHA-256 and SHA-384 with K extension acceleration.

**Interface:**
```c
int hash_init(hash_context_t *ctx, uint32_t algo);
int hash_update(hash_context_t *ctx, const uint8_t *data, size_t len);
int hash_final(hash_context_t *ctx, uint8_t *digest, size_t *digest_len);
void hash_free(hash_context_t *ctx);
```

**Implementation Strategy:**
- When `__riscv_zk` is defined: uses K extension intrinsics for SHA
- Otherwise: uses mbedTLS software implementation
- Compile with `-march=rv64gc_zk` to enable K extension

### 2. ECDSA Module (ecdsa.h/ecdsa.c)

Full ECDSA P-256 verification using **RISC-V Vector Extension (RVV)** for point arithmetic.

**Interface:**
```c
int ecdsa_verify(const uint8_t *pubkey, size_t pubkey_len,
                 uint32_t algo,  // SIG_ALGO_ECDSA_P256 or SIG_ALGO_ECDSA_P384
                 const uint8_t *hash, size_t hash_len,
                 const uint8_t *signature, size_t sig_len);
```

**Supported curves:**
- P-256 (secp256r1, 256-bit) — **native RVV implementation**
- P-384 (secp384r1, 384-bit) — via mbedTLS

#### RVV Implementation Details

The P-256 ECDSA verification uses RVV for parallel limb operations:

| Operation | RVV Usage |
|-----------|-----------|
| 4× uint64_t load/store | `vlseg4e64.v` / `vsseg4e64.v` (single instruction) |
| Modular add/sub | Vector parallel limb operations |
| Modular reduction | Vector shifts for P-256 special-form reduction |
| Scalar mul | `__uint128_t` MUL (RVV has no modular mul) |

**Note:** RISC-V has **no EC point multiplication instructions** in any extension. The full ECDSA verification (point add/double/multiply) is implemented in software using RVV for parallel big-int limb operations.

#### Algorithm: ECDSA Verification with Montgomery Ladder

```
1. Parse r, s from signature
2. w = s^(-1) mod n
3. u1 = e * w mod n, u2 = r * w mod n
4. R = u1*G + u2*Q  (using Montgomery ladder scalar multiplication)
5. Verify R.x mod n == r
```

**Montgomery Ladder** provides constant-time execution (no secret-dependent branches):
- Always performs both point addition and doubling per bit
- Uses cswap to select results based on the key bit
- Resistant to timing attacks

#### Jacobian Point Arithmetic

Point operations use Jacobian coordinates for efficiency:
- **Point doubling**: 4M + 4S + 1add (a = -3 optimized)
- **Point addition** (mixed): 7M + 4S + 1add
- **Affine conversion**: 2M + 1inv (modular inverse)

#### Fixed P-256 Curve Parameters

All P-256 constants are baked in as `static const` at compile time:

| Parameter | Value | Purpose |
|----------|-------|---------|
| `P256_P` | `2^256 - 2^224 + 2^192 + 2^96 - 1` | Prime field modulus |
| `P256_N` | `0xFC632551...` | Curve order (number of points) |
| `P256_A` | `-3 mod p` | Curve coefficient `a = -3` |
| `P256_B` | `0xE8B5B10C...` | Curve coefficient `b` |
| `P256_GX/GY` | Base point G | Generator point |

This eliminates runtime constant loading and table lookups, reducing branching and memory access.

#### Constant-Time Arithmetic (RISC-V B Extension)

Big-int operations use B extension intrinsics for constant-time execution:

```c
// Constant-time conditional select (cmix)
ct_select(sel, if_true, if_false)  // selects without branch

// Constant-time zero check
ct_is_zero(x)  // returns 1 if x==0, 0 otherwise
```

**Big-int operations (4x uint64_t = 256-bit):**
- `p256_add_full()` / `p256_sub_full()` — full 256-bit add/subtract with carry/borrow
- `p256_mod_add()` / `p256_mod_sub()` — modular add/subtract with constant-time reduction
- `p256_mul()` — 256-bit × 256-bit → 512-bit (schoolbook, no secret-dependent branches)
- `p256_mod_reduce()` — fast reduction for P-256 prime using its special form
- `p256_mod_inv()` — modular inverse via fixed-window exponentiation (constant-time)
- `p256_is_zero()` / `p256_ge()` — constant-time comparisons

#### P-256 Prime Reduction Optimization

The P-256 prime `p = 2^256 - 2^224 + 2^192 + 2^96 - 1` has a special form enabling fast reduction:

```
2^256 ≡ 2^224 - 2^192 - 2^96 + 1 (mod p)
```

This allows 512-bit → 256-bit reduction in 2 iterations without generic division.

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

- **Target**: RISC-V with K + V extensions (Zk + RVV)
- **Compiler**: GCC for RISC-V with `-march=rv64gcv_zk`
- **SHA hash**: K extension intrinsics (Zknh) when available
- **ECDSA P-256**: Native implementation with RVV acceleration
- **ECDSA P-384**: mbedTLS software fallback

### Build Flags

| Flag | Purpose |
|------|---------|
| `-D__riscv_zk` | Enable K extension intrinsics (SHA) |
| `-D__riscv_rvv` | Enable RVV intrinsics (ECDSA) |
| `-march=rv64gcv_zk` | Target RISC-V with G + C + V + Zk |
| `-mabi=lp64d` | 64-bit ABI with double-precision float |

### Build Targets

| Target | Extensions | SHA | ECDSA |
|--------|-----------|-----|-------|
| `make build-kv` | rv64gcv_zk | K intrinsics | **RVV native** |
| `make build-k` | rv64gc_zk | K intrinsics | mbedTLS |
| `make build-base` | rv64gc | Software | mbedTLS |

## File Structure

| File | Description |
|------|-------------|
| `include/image_header.h` | Header structure definition and constants |
| `include/hash.h/c` | SHA-256/SHA-384 (K extension + mbedTLS fallback) |
| `include/ecdsa.h/c` | Native P-256 ECDSA with RVV + mbedTLS fallback |
| `include/verify.h/c` | Image verification entry point |
| `keys/ecdsa_pubkey.h/c` | Embedded public key |
| `src/image_tool.c` | Utility to create signed images |
| `Makefile` | Build configuration with K extension support |

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
