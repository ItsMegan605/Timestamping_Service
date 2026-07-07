/**
 * crypto.h - Cryptographic helpers for hashing, signing, and TLS setup.
 * 
 * TODO: Declare functions to:
 *   - Compute SHA-256 of a file or memory buffer.
 *   - Load PEM public/private keys (EVP_PKEY*).
 *   - Sign (hash || time) with the timestamp private key.
 *   - Verify (hash || time) with the timestamp public key.
 *   - Set up TLS client/server contexts with PFS (TLS 1.3 + ECDHE).
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <string>
#include <cstdint>
#include <openssl/ssl.h>
#include <openssl/evp.h>

// ---------- Hashing ----------
// TODO: std::array<uint8_t, 32> sha256_file(const std::string& filename)
// TODO: std::array<uint8_t, 32> sha256_data(const std::vector<uint8_t>& data)

// ---------- Key Loading ----------
// TODO: EVP_PKEY* load_public_key(const std::string& pem_file)
// TODO: EVP_PKEY* load_private_key(const std::string& pem_file)

// ---------- Signing & Verification ----------
// TODO: std::vector<uint8_t> sign_timestamp(const std::array<uint8_t, 32>& hash,
//                                           uint64_t timestamp,
//                                           EVP_PKEY* private_key)
// TODO: bool verify_timestamp(const std::array<uint8_t, 32>& hash,
//                             uint64_t timestamp,
//                             const std::vector<uint8_t>& signature,
//                             EVP_PKEY* public_key)

// ---------- TLS Setup ----------
// TODO: SSL_CTX* create_tls_client_ctx(const std::string& ca_cert_file)
// TODO: SSL_CTX* create_tls_server_ctx(const std::string& cert_file,
//                                      const std::string& key_file)

#endif // CRYPTO_H