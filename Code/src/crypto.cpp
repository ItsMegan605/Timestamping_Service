#include "../header_files/crypto.h"
#include "../header_files/common.h"
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iostream>
#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <cstdio>
// TODO: (Includes) Add the following headers for X.509 and memory clearing operations
// #include <openssl/x509.h>
// #include <openssl/x509_vfy.h>
// #include <openssl/crypto.h> // for OPENSSL_cleanse

using namespace std;

// ==============================================================================
// SHA-256 HASHING FUNCTIONS
// ==============================================================================

/**
 * sha256_data
 * Computes the SHA-256 hash of a raw byte vector using the OpenSSL EVP API.
 * This is the standard, secure way to hash data in memory.
 * Follows the standard hash context creation
 */
array<uint8_t, 32> sha256_data(const vector<uint8_t>& data) {
    array<uint8_t, 32> hash = {}; 

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        cerr << "ERROR: failed to create hash context" << endl;
        return hash; 
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        cerr << "ERROR: failed to initialize SHA-256" << endl;
        EVP_MD_CTX_free(ctx);
        return hash; 
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        cerr << "ERROR: failed to update SHA-256 with data" << endl;
        EVP_MD_CTX_free(ctx);
        return hash;
    }

    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1 ) {
        cerr << "ERROR: failed to finalize SHA-256" << endl;
        EVP_MD_CTX_free(ctx);
        return hash;
    }

    if (hash_len != 32) {
        cerr << "ERROR: unexpected hash length: " << hash_len << endl;
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

/**
 * sha256_data (overload)
 * Convenience wrapper to compute the SHA-256 hash of a std::string.
 * Useful for hashing salted passwords.
 */
array<uint8_t, 32> sha256_data(const string& data) {
    vector<uint8_t> bytes(data.begin(), data.end());
    return sha256_data(bytes);
}

/**
 * sha256_file
 * Computes the SHA-256 hash of a file's contents.
 * Reads the file in 8KB chunks to maintain a low RAM footprint regardless of file size.
 */
array<uint8_t, 32> sha256_file(const string& filename) {
    array<uint8_t, 32> hash = {}; 

    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) {
        cerr << "ERROR: failed to open file: " << filename << endl;
        return hash; 
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        cerr << "ERROR: failed to create hash context" << endl;
        fclose(file);
        return hash; 
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        cerr << "ERROR: failed to initialize SHA-256" << endl;
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return hash; 
    }

    const size_t buffer_size = 8192; 
    vector<uint8_t> buffer(buffer_size);
    size_t bytes_read = 0;

    while ((bytes_read = fread(buffer.data(), 1, buffer_size, file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer.data(), bytes_read) != 1) {
            cerr << "ERROR: failed to update SHA-256 from file chunk" << endl;
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return hash; 
        }
    }

    if (ferror(file)) {
        cerr << "ERROR: error reading file while hashing: " << filename << endl;
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return hash; 
    }

    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1 ) {
        cerr << "ERROR: failed to finalize SHA-256 for file" << endl;
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return hash; 
    }

    EVP_MD_CTX_free(ctx);
    fclose(file);

    return hash;
}

// ==============================================================================
// HKDF IMPLEMENTATION (HMAC-based Key Derivation Function)
// ==============================================================================

/**
 * hmac_sha256
 * Internal helper function. Computes the HMAC-SHA256 of the given data using the specified key.
 */
static array<uint8_t, 32> hmac_sha256(const vector<uint8_t>& key, const vector<uint8_t>& data) {
    array<uint8_t, 32> result;
    unsigned int result_len = 0;   

    if (HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), result.data(), &result_len) == NULL) {
        cerr << "ERROR: HMAC-SHA256 failed" << endl;
        result.fill(0); 
        return result;
    }

    if (result_len != 32) {
        cerr << "WARNING : unexpected HMAC length: " << result_len << endl;
    }

    return result;
}       

/**
 * hkdf_extract
 * Phase 1 of HKDF. Extracts a fixed-length pseudorandom key (PRK) from the shared secret,
 * using the concatenated nonces as the salt.
 */
static array<uint8_t, 32> hkdf_extract(const vector<uint8_t>& salt, const vector<uint8_t>& ikm) {
    return hmac_sha256(salt, ikm);
}

/**
 * hkdf_expand
 * Phase 2 of HKDF. Expands the PRK into the desired output length (AES Key + IV).
 */
static vector<uint8_t> hkdf_expand(const array<uint8_t, 32>& prk, const string& info, size_t out_len) {
    vector<uint8_t> output; 
    output.reserve(out_len);

    vector<uint8_t> T_prev; 
    uint8_t counter = 1;

    while (output.size() < out_len) {
        vector<uint8_t> input;
        input.insert(input.end(), T_prev.begin(), T_prev.end());    
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);

        array<uint8_t, 32> T_i = hmac_sha256(vector<uint8_t>(prk.begin(), prk.end()), input);
        output.insert(output.end(), T_i.begin(), T_i.end());
        T_prev.assign(T_i.begin(), T_i.end());
        counter++;

        if (counter == 0) {
            cerr << "ERROR: HKDF-Expand counter overflow" << endl;
            break;
        }
    }

    output.resize(out_len);
    return output;
}

/**
 * hkdf_extract_expand
 * Public interface for HKDF. Takes the raw ECDH shared secret and nonces,
 * and derives a secure 32-byte AES key and a 12-byte IV for AES-GCM.
 */
bool hkdf_extract_expand(const vector<uint8_t>& shared_secret, 
                        const vector<uint8_t>& client_nonce,
                        const vector<uint8_t>& server_nonce, 
                        vector<uint8_t>& out_enc_key,
                        vector<uint8_t>& out_iv) {

    if (shared_secret.empty() || client_nonce.size() != NONCE_SIZE || server_nonce.size() != NONCE_SIZE) {
        cerr << "ERROR: Invalid inputs to HKDF" << endl;
        return false;
    }

    vector<uint8_t> salt;
    salt.reserve(NONCE_SIZE * 2);
    salt.insert(salt.end(), client_nonce.begin(), client_nonce.end());
    salt.insert(salt.end(), server_nonce.begin(), server_nonce.end());

    array<uint8_t, 32> prk = hkdf_extract(salt, shared_secret);

    const size_t AES_KEY_LEN = 32;
    const size_t IV_LEN = 12;
    const size_t TOTAL_LEN = AES_KEY_LEN + IV_LEN;
    const string info = "tss_session_key";

    vector<uint8_t> expanded = hkdf_expand(prk, info, TOTAL_LEN);

    if (expanded.size() != TOTAL_LEN) {
        cerr << "ERROR: HKDF-Expand produced unexpected length" << endl;
        return false;
    }

    out_enc_key.assign(expanded.begin(), expanded.begin() + AES_KEY_LEN);
    out_iv.assign(expanded.begin() + AES_KEY_LEN, expanded.end());

    // TODO: (PFS) Explicitly clear the PRK and expanded buffers from memory before returning
    // OPENSSL_cleanse(prk.data(), prk.size());
    // OPENSSL_cleanse(expanded.data(), expanded.size());

    return true; 
}


// ==============================================================================
// ECDH & EPHEMERAL KEYS
// ==============================================================================

/**
 * generate_ephemeral_key
 * Generates an ephemeral Elliptic Curve key pair (P-256) for Perfect Forward Secrecy.
 */
EVP_PKEY* generate_ephemeral_key() {
    EVP_PKEY* dh_params = NULL;
    EVP_PKEY_CTX* ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    
    if (!ctx_params) {
        cerr << "Error creating parameter context" << endl;
        return NULL;
    }

    EVP_PKEY_paramgen_init(ctx_params);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx_params, NID_X9_62_prime256v1);
    EVP_PKEY_paramgen(ctx_params, &dh_params);
    EVP_PKEY_CTX_free(ctx_params);

    EVP_PKEY* ephemeral_key = NULL;
    EVP_PKEY_CTX* ctx_key = EVP_PKEY_CTX_new(dh_params, NULL);
    
    if (!ctx_key) {
        cerr << "Error creating key context" << endl;
        EVP_PKEY_free(dh_params);
        return NULL;
    }

    EVP_PKEY_keygen_init(ctx_key);
    EVP_PKEY_keygen(ctx_key, &ephemeral_key);
    
    EVP_PKEY_CTX_free(ctx_key);
    EVP_PKEY_free(dh_params);

    return ephemeral_key;
}

/**
 * generate_nonce
 * Fills a vector with cryptographically secure random bytes to prevent replay attacks.
 */
vector<uint8_t> generate_nonce(size_t length) {
    vector<uint8_t> nonce(length);
    if (RAND_bytes(nonce.data(), length) != 1) {
        cerr << "Critical error: unable to generate entropy for nonce." << endl;
        exit(EXIT_FAILURE); 
    }
    return nonce;
}

/**
 * serialize_pubkey
 * Converts an internal OpenSSL EVP_PKEY structure into a raw DER byte format for transmission.
 */
vector<uint8_t> serialize_pubkey(EVP_PKEY* pkey) {
    unsigned char* buf = nullptr;
    int len = i2d_PUBKEY(pkey, &buf);
    vector<uint8_t> result(buf, buf + len);
    OPENSSL_free(buf);
    return result;
}

/**
 * deserialize_pubkey
 * Parses a raw DER byte format back into an OpenSSL EVP_PKEY structure.
 */
EVP_PKEY* deserialize_pubkey(const vector<uint8_t>& pubkey_bytes) {
    const unsigned char* ptr = pubkey_bytes.data();
    return d2i_PUBKEY(NULL, &ptr, pubkey_bytes.size());
}


// ==============================================================================
// SIGNATURES
// ==============================================================================

/**
 * sign_data
 * Computes a digital signature over the given data using the provided private key and SHA-256.
 */
vector<uint8_t> sign_data(const vector<uint8_t>& data, EVP_PKEY* priv_key) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        cerr << "Error creating message digest context" << endl;
        return {};
    }
    size_t sig_len;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv_key) <= 0) {
        cerr << "Error initializing signature operation" << endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    if (EVP_DigestSign(ctx, NULL, &sig_len, data.data(), data.size()) <= 0) {
        cerr << "Error determining signature length" << endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    vector<uint8_t> signature(sig_len);
    if (EVP_DigestSign(ctx, signature.data(), &sig_len, data.data(), data.size()) <= 0) {
        cerr << "Error generating signature" << endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    EVP_MD_CTX_free(ctx);
    return signature;
}

/**
 * verify_signature
 * Verifies the authenticity and integrity of data using a public key and SHA-256.
 */
bool verify_signature(const vector<uint8_t>& data, const vector<uint8_t>& signature, EVP_PKEY* pub_key) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool result = false;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub_key) > 0) {
        if (EVP_DigestVerify(ctx, signature.data(), signature.size(), data.data(), data.size()) == 1) {
            result = true; 
        }
    }
    
    EVP_MD_CTX_free(ctx);
    return result;
}

// ==============================================================================
// KEY LOADING
// ==============================================================================

EVP_PKEY* load_private_key(const string& filepath) {
    FILE* fp = fopen(filepath.c_str(), "r");
    if (!fp) { cerr << "Error opening " << filepath << endl; return nullptr; }
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return pkey;
}

EVP_PKEY* load_public_key(const string& filepath) {
    FILE* fp = fopen(filepath.c_str(), "r");
    if (!fp) { cerr << "Error opening " << filepath << endl; return nullptr; }
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return pkey;
}


// ==============================================================================
// ECDH DERIVATION
// ==============================================================================

/**
 * derive_shared_secret
 * Computes the mathematical shared secret by combining the local private ephemeral key 
 * with the peer's public ephemeral key.
 * NOTE: Fixed memory leaks by ensuring the context is freed on error paths.
 */
bool derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pub_key, vector<uint8_t>& out_secret) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) return false;

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    size_t secret_len;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    out_secret.resize(secret_len);
    if (EVP_PKEY_derive(ctx, out_secret.data(), &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    
    // TODO: (PFS) It is up to the caller to cleanse the 'out_secret' buffer using 
    // OPENSSL_cleanse(out_secret.data(), out_secret.size()) immediately after 
    // passing it to the HKDF module, ensuring the raw material is removed from RAM.
    return true;
}

// ===========================================================================
// AES_GCM_256
// ===========================================================================
int encrypt_aes_gcm_256 (const unsigned char *plaintext, int plaintext_len,
                        const unsigned char *aad, int aad_len,
                        const unsigned char *key, const unsigned char *iv,
                        unsigned char *ciphertext, unsigned char *tag) {

EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
if (!ctx){
    cerr << "Error" << endl;
    return -1;
    }

    int len = 0;
    int ciphertext_len = 0;

if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int decrypt_aes_gcm_256 (const unsigned char *ciphertext, int ciphertext_len,
                        const unsigned char *aad, int aad_len,
                        const unsigned char *key, const unsigned char *iv,
                        unsigned char *plaintext, unsigned char *tag) {

EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
if (!ctx){
    cerr << "Error" << endl;
    return -1;
    }

    int len = 0;
    int plaintext_len = 0;

if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1 ){
    EVP_CIPHER_CTX_free(ctx);
    return -1;
    }
}

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; 
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}



// ==============================================================================
// TODO BLOCKS: MISSING CRYPTOGRAPHIC ARCHITECTURE (X.509 & AES-GCM)
// ==============================================================================

// TODO: [X.509 CERTIFICATE MANAGEMENT]
// Add functions to handle X.509 certificates to comply with the architecture specs:
// 1. `X509* load_certificate(const string& filepath)`
//    Uses `PEM_read_X509` to load a certificate from disk (used by the Server).
// 2. `vector<uint8_t> serialize_certificate(X509* cert)`
//    Uses `i2d_X509` to encode the certificate to DER format for network transmission.
// 3. `X509* deserialize_certificate(const vector<uint8_t>& cert_bytes)`
//    Uses `d2i_X509` to decode the received DER bytes into an X509 object (used by the Client).
// 4. `EVP_PKEY* extract_pubkey_from_cert(X509* cert)`
//    Uses `X509_get_pubkey` to securely extract the long-term public key to verify signatures.
// 5. `bool verify_certificate(X509* cert, const string& ca_cert_filepath)`
//    - Creates a store: `X509_STORE_new()`
//    - Loads the CA root: `X509_STORE_add_cert()`
//    - Creates context: `X509_STORE_CTX_new()` and `X509_STORE_CTX_init()`
//    - Validates: `X509_verify_cert()`
//    - Cleans up memory.
