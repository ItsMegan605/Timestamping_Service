/**
 * crypto.h - Cryptographic helpers for hashing, signing, and TLS setup.
 * 
 * TODO: Declare functions to:
 *   - Compute SHA-256 of a file or memory buffer.
 *   - Load PEM public/private keys (EVP_PKEY*).
 *   - Sign (hash || time) with the timestamp private key.
 *   - Verify (hash || time) with the timestamp public key.
 *   - Set up client/server contexts with PFS (ECDHE).
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include <openssl/ssl.h>
#include <openssl/evp.h>

std::vector<uint8_t> generate_nonce(size_t length);
EVP_PKEY* generate_ephemeral_key();

// ---------- Hashing ----------
// TODO: std::array<uint8_t, 32> sha256_file(const std::string& filename)
// TODO: std::array<uint8_t, 32> sha256_data(const std::vector<uint8_t>& data)

// ---------- Key Loading (PEM) ----------
// TODO: EVP_PKEY* load_public_key(const std::string& pem_file)
// TODO: EVP_PKEY* load_private_key(const std::string& pem_file)

// ---------- ECDH Shared Secret ----------
// TODO: bool derive_shared_secret(EVP_PKEY* my_priv_key,
//                                 EVP_PKEY* peer_pub_key,
//                                 std::vector<uint8_t>& out_secret)

// ---------- HKDF (key derivation from shared secret) ----------
// TODO: bool hkdf_extract_expand(const std::vector<uint8_t>& shared_secret,
//                                const std::vector<uint8_t>& client_nonce,
//                                const std::vector<uint8_t>& server_nonce,
//                                std::vector<uint8_t>& out_enc_key,
//                                std::vector<uint8_t>& out_iv)

// ---------- AES-GCM Encryption / Decryption ----------
// TODO: bool aes_gcm_encrypt(const std::vector<uint8_t>& key,
//                            const std::vector<uint8_t>& iv,
//                            const std::vector<uint8_t>& aad,   // e.g., sequence number
//                            const std::vector<uint8_t>& plaintext,
//                            std::vector<uint8_t>& out_ciphertext,
//                            std::vector<uint8_t>& out_tag)

// TODO: bool aes_gcm_decrypt(const std::vector<uint8_t>& key,
//                            const std::vector<uint8_t>& iv,
//                            const std::vector<uint8_t>& aad,
//                            const std::vector<uint8_t>& ciphertext,
//                            const std::vector<uint8_t>& tag,
//                            std::vector<uint8_t>& out_plaintext)


// ---------- Signing & Verification (for Handshake) ----------
// TODO: std::vector<uint8_t> sign_data(const std::vector<uint8_t>& data,
//                                      EVP_PKEY* private_key)
// TODO: bool verify_signature(const std::vector<uint8_t>& data,
//                             const std::vector<uint8_t>& signature,
//                             EVP_PKEY* public_key)

// ---------- Signing & Verification (for Timestamp) ----------
// IMPORTANT: The timestamp MUST be converted to network byte order (big-endian)
// using htobe64() BEFORE concatenating with the hash and signing.
// This ensures cross-platform compatibility.
// TODO: std::vector<uint8_t> sign_timestamp(const std::array<uint8_t, 32>& hash,
//                                           uint64_t timestamp_ns,
//                                           EVP_PKEY* private_key)
// TODO: bool verify_timestamp(const std::array<uint8_t, 32>& hash,
//                             uint64_t timestamp_ns,
//                             const std::vector<uint8_t>& signature,
//                             EVP_PKEY* public_key)

#endif // CRYPTO_H