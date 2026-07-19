#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include <openssl/ssl.h>
#include <openssl/evp.h>

using namespace std;

// --- ECDH & Ephemeral Keys ---
vector<uint8_t> generate_nonce(size_t length);
EVP_PKEY* generate_ephemeral_key();
vector<uint8_t> serialize_pubkey(EVP_PKEY* pkey);
EVP_PKEY* deserialize_pubkey(const vector<uint8_t>& pubkey_bytes);

// --- Signatures ---
vector<uint8_t> sign_data(const vector<uint8_t>& data, EVP_PKEY* priv_key);
bool verify_signature(const vector<uint8_t>& data, const vector<uint8_t>& signature, EVP_PKEY* pub_key);

// --- SHA-256 Hashing ---
array<uint8_t, 32> sha256_data(const vector<uint8_t>& data);
array<uint8_t, 32> sha256_data(const string& data);
array<uint8_t, 32> sha256_file(const string& filename);

// --- Key Loading ---
EVP_PKEY* load_private_key(const string& filepath);
EVP_PKEY* load_public_key(const string& filepath);

// --- Key Derivation (ECDH & HKDF) ---
bool derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pub_key, vector<uint8_t>& out_secret);

// Derives AES key (32 bytes) and IV (12 bytes) using HKDF-SHA256
bool hkdf_extract_expand(const vector<uint8_t>& shared_secret,
                        const vector<uint8_t>& client_nonce,
                        const vector<uint8_t>& server_nonce,
                        vector<uint8_t>& out_enc_key,
                        vector<uint8_t>& out_iv);

// --- AES-GCM 256 ---
int encrypt_aes_gcm_256(const unsigned char *plaintext, int plaintext_len,
                        const unsigned char *aad, int aad_len,
                        const unsigned char *key, const unsigned char *iv,
                        unsigned char *ciphertext, unsigned char *tag);

int decrypt_aes_gcm_256(const unsigned char *ciphertext, int ciphertext_len,
                        const unsigned char *aad, int aad_len,
                        const unsigned char *key, const unsigned char *iv,
                        unsigned char *plaintext, unsigned char *tag);

#endif // CRYPTO_H