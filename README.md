# Secure Boot Image Verification

A modular C implementation for RISC-V secure boot image verification using ECDSA signatures, with hardware acceleration via RISC-V K extension (Zk).

## Features

- ECDSA P-256 signature verification with **RVV (Vector Extension)** acceleration
- ECDSA P-384 verification via mbedTLS
- SHA-256/SHA-384 hash support with **K extension acceleration**
- **Fixed P-256 curve parameters** for reduced runtime overhead
- **Constant-time arithmetic** via RISC-V B extension (cmix/cmov)
- **Full ECDSA point multiplication** using Jacobian coordinates + Montgomery ladder
- Modular architecture (hash, ECDSA, verify modules)
- Embedded public key for verification
- Image packaging tool

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Secure Boot Library                       │
├─────────────────────────────────────────────────────────────┤
│  verify_image()                                              │
│  ├── hash (SHA via K extension)                            │
│  │   └── Uses _sha256sig0/sum0, _sha512sig0/sum0 intrinsics │
│  └── ecdsa_verify (P-256 via RVV)                        │
│      ├── Fixed P-256 parameters (P, N, G, A, B)            │
│      ├── Constant-time big-int (B extension cmix)           │
│      ├── Vector modular ops (RVV add/sub/shift)            │
│      ├── Jacobian point arithmetic (double/add)             │
│      └── Montgomery ladder scalar multiplication            │
└─────────────────────────────────────────────────────────────┘
```

### Hardware Acceleration Summary

| Component | Acceleration | Implementation |
|-----------|-------------|----------------|
| SHA-256/512 hash | ✅ K extension | `_sha256sig0/sum0` intrinsics |
| ECDSA P-256 point mul | ✅ RVV | Jacobian coords + Montgomery ladder |
| ECDSA P-384 | ❌ Software | mbedTLS |

### RISC-V Extensions Used

**K extension (Zk) = Zkn + Zkr + Zkt:**
- **Zknh** = SHA-256/SHA-512 intrinsics
- **Zkt** = Constant-time execution guarantee

**V extension (RVV) for ECDSA:**
- Vector loads/stores for 4-limb P-256 values (single instruction)
- Vector add/sub for parallel modular arithmetic
- Vector shifts for reduction operations
- Note: Modular multiplication uses scalar MUL; RVV assists with reduction

### ECDSA P-256: Fixed Curve Parameters

ECDSA P-256 verification uses **fixed compile-time constants** to eliminate runtime loading:

| Parameter | Description |
|-----------|-------------|
| `P256_P` | Prime modulus: `2^256 - 2^224 + 2^192 + 2^96 - 1` |
| `P256_N` | Curve order: number of points on the curve |
| `P256_GX/GY` | Generator point (base point) |
| `P256_A = -3` | Curve coefficient `a = -3 mod p` |
| `P256_B` | Curve coefficient `b` |

**Constant-time big-int operations** (RISC-V B extension):
- `ct_select()` — constant-time conditional select via `cmix`
- `ct_is_zero()` — constant-time zero check
- `p256_mod_add/sub/mul` — modular arithmetic without branches

**Fast P-256 prime reduction** using the special form:
```
2^256 ≡ 2^224 - 2^192 - 2^96 + 1 (mod p)
```
This allows 512-bit → 256-bit reduction in 2 iterations without division.

## Building

### Prerequisites

- RISC-V GCC toolchain (with Zk + V extensions)
- mbedTLS library (for P-384 ECDSA fallback)
- Git submodules

### Build

```bash
# Initialize submodules (riscv-crypto + mbedTLS)
git submodule update --init

# Build with K + V extensions (full acceleration)
make

# Or build with explicit targets
make build-kv    # K + V (SHA + ECDSA P-256)
make build-k     # K only (SHA, ECDSA via mbedTLS)
make build-base  # No extensions (pure software)
```

### Build Options

| Target | Extensions | SHA | ECDSA P-256 |
|--------|-----------|-----|--------------|
| `build-kv` | rv64gcv_zk | K intrinsics | **RVV + native** |
| `build-k` | rv64gc_zk | K intrinsics | mbedTLS |
| `build-base` | rv64gc | Software | mbedTLS |

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

- **Hash computation**: `SHA(header || image_data)`
- **Signature**: ECDSA P-256/P-384 signature over hash

### Header Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | version | Image version (e.g., 0x00010000 = 1.0.0) |
| 4 | 4 | image_type | Image type identifier |
| 8 | 4 | image_length | Image data length (bytes) |
| 12 | 4 | flags | Flags |
| 16 | 8 | timestamp | Build timestamp |
| 24 | 4 | hash_algo | 0=SHA256, 1=SHA384 |
| 28 | 4 | sig_algo | 0=ECDSA_P256, 1=ECDSA_P384 |

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
├── include/           # Header files
│   ├── image_header.h # Header structure
│   ├── hash.h         # Hash interface
│   ├── ecdsa.h        # ECDSA interface
│   └── verify.h      # Verification interface
├── src/               # Source files
│   ├── hash.c         # Hash (K extension + mbedTLS fallback)
│   ├── ecdsa.c        # ECDSA (mbedTLS)
│   ├── verify.c       # Verification logic
│   └── image_tool.c   # Image signing tool
├── keys/              # Public key
│   ├── ecdsa_pubkey.h
│   └── ecdsa_pubkey.c
├── thirdparty/
│   ├── riscv-crypto/  # K extension intrinsics
│   └── mbedtls/       # ECDSA crypto library
├── Makefile
└── README.md
```

## RISC-V K Extension Intrinsics

The library uses the following intrinsics from `riscv-crypto-intrinsics.h`:

```c
// SHA-256
_sha256sig0(rs1)   // σigma0
_sha256sig1(rs1)   // σigma1
_sha256sum0(rs1)   // Σigma0
_sha256sum1(rs1)   // Σigma1

// SHA-512 (RV64 only)
_sha512sig0(rs1)   // σigma0
_sha512sig1(rs1)   // σigma1
_sha512sum0(rs1)   // Σigma0
_sha512sum1(rs1)   // Σigma1
```

These are enabled when compiling with `-D__riscv_zk` (implied by `-march=rv64gc_zk`).
