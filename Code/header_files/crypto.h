#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include <openssl/ssl.h>
#include <openssl/evp.h>

using namespace std;

vector<uint8_t> generate_nonce(size_t length);
EVP_PKEY* generate_ephemeral_key();
vector<uint8_t> serialize_pubkey(EVP_PKEY* pkey);
EVP_PKEY* deserialize_pubkey(const vector<uint8_t>& pubkey_bytes); // AGGIUNTA
vector<uint8_t> sign_data(const vector<uint8_t>& data, EVP_PKEY* priv_key);
bool verify_signature(const vector<uint8_t>& data, const vector<uint8_t>& signature, EVP_PKEY* pub_key);

// for SHA256 hashing
/*
computes the SHA-256 hash of raw data
@param data the input data to hash
@return array<uint8_t, 32> the 32-byte hash
Use case: hashing paswords (with salt) for database storage
*/
array<uint8_t, 32> sha256_data(const vector<uint8_t>& data);

/*
Convenience overload for hashing strings
@param data the input string to hash
@return array<uint8_t, 32> the 32-byte hash
*/
array<uint8_t, 32> sha256_data(const string& data);

/*
Computes the SHA-256 hash of a file's contents
@param filename the path to the file to hash
@return array<uint8_t, 32> the 32-byte hash

Use case: users timestamping files - they do this locally, and then send the hash to the server for signing. The server does not need to see the file itself, only its hash.
@note reads the file in chunks to handle large files efficiently
*/
array<uint8_t, 32> sha256_file(const string& filename);

// signing and verifivation
vector<uint8_t> sign_data(const vector<uint8_t>& data, EVP_PKEY* priv_key);
bool verify_signature(const vector<uint8_t>& data, const vector<uint8_t>& signature, EVP_PKEY* pub_key);


// key loading
EVP_PKEY* load_private_key(const string& filepath);
EVP_PKEY* load_public_key(const string& filepath);

// ECDH shared secret derivation
bool derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pub_key, vector<uint8_t>& out_secret);

#endif // CRYPTO_H