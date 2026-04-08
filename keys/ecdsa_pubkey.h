#ifndef ECDSA_PUBKEY_H
#define ECDSA_PUBKEY_H

// ECDSA P-256 public key (uncompressed format: 0x04 || x || y)
// This is a placeholder key - replace with actual production key
extern const uint8_t ecdsa_public_key[];
extern const size_t ecdsa_public_key_len;

// For P-256: key is 65 bytes (0x04 || 32-byte X || 32-byte Y)
// For P-384: key is 97 bytes (0x04 || 48-byte X || 48-byte Y)

#endif // ECDSA_PUBKEY_H
