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

EVP_PKEY* load_private_key(const string& filepath);
EVP_PKEY* load_public_key(const string& filepath);
bool derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pub_key, vector<uint8_t>& out_secret);

#endif // CRYPTO_H