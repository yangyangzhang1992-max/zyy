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
