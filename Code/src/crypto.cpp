#include "../header_files/crypto.h"
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
#include <cstdio> 

using namespace std;

// SHA-256 hashing functions
/*
this computes the SHA-256 hash of raw data usinf the OpenSSL EVP interface
as follows:
1. creates a hash context (EVP_MD_CTX) which holds the state of the hash 
2. initializes the context for SHA-256 hashing
3. feeds the input data into the hash context(EVP_DigestUpdate)
4. finalizes the hash and extracts the 32-byte result
5. cleans up the context to free resources
*/
array<uint8_t, 32> sha256_data(const vector<uint8_t>& data) {
    array<uint8_t, 32> hash = {}; // initialize to zero (incase of errors, we want a known state)

    // Create a new hash context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        cerr << "ERROR: failed to create hash context" << endl;
        return hash; // return zeroed hash on error
    }

    // initialize the context for SHA-256 hashing, EVP_sha256() returns the SHA-256 algorithm object
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        cerr << "ERROR: failed to initialize SHA-256" << endl;
        EVP_MD_CTX_free(ctx);
        return hash; 
    }

    // feed the input data into the hash, EVP_DigestUpdate() can be called multiple times for streaming data
    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        cerr << "ERROR: failed to update SHA-256 with data" << endl;
        EVP_MD_CTX_free(ctx);
        return hash;
    }

    // finalize the hash and extract the resukt
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1 ) {
        cerr << "ERROR: failed to finalize SHA-256" << endl;
        EVP_MD_CTX_free(ctx);
        return hash;
    }

    //hash_len should be 32 for SHA-256, but we can check to be sure
    if (hash_len != 32) {
        cerr << "ERROR: unexpected hash length: " << hash_len << endl;
    }

    // free the context
    EVP_MD_CTX_free(ctx);


    return hash;
}

/*
Convenience overload for hashing strings
this just converts the string to bytes and calls the main function
Use case: hashing passwords and othe text data
*/
array<uint8_t, 32> sha256_data(const string& data) {
    vector<uint8_t> bytes(data.begin(), data.end());
    return sha256_data(bytes);
}

/*
Computes the SHA-256 hash of a file's contents as follows:
1. opens the file in binary mode("rb")
2. creates and initializes a SHA-256 hash context
3. reads the file in 8KB chunks 
4. for each chunk, calls EVP_DigestUpdate to feed the data into the hash 
5. when EOF is reached, finalizes the hash 
6. cleans up the context and closes the file
*/
array<uint8_t, 32> sha256_file(const string& filename) {
    array<uint8_t, 32> hash = {}; 

    // open the file in binary mode
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) {
        cerr << "ERROR: failed to open file: " << filename << endl;
        return hash; 
    }

    // create and initialize the hash context
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

    // read the file in 8KB chunks  
    const size_t buffer_size = 8192; // 8KB buffer
    vector<uint8_t> buffer(buffer_size);
    size_t bytes_read = 0;

    while ((bytes_read = fread(buffer.data(), 1, buffer_size, file)) > 0) {
        // feed the chunk into the hash
        if (EVP_DigestUpdate(ctx, buffer.data(), bytes_read) != 1) {
            cerr << "ERROR: failed to update SHA-256 from file chunk" << endl;
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return hash; 
        }
    }

    // check if fread failed due to an error (not just EOF)
    if (ferror(file)) {
        cerr << "ERROR: error reading file while hashing: " << filename << endl;
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return hash; 
    }

    // finalize the hash
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1 ) {
        cerr << "ERROR: failed to finalize SHA-256 for file" << endl;
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return hash; 
    }

    // clean up
    EVP_MD_CTX_free(ctx);
    fclose(file);

    return hash;
}

// generates an ephemeral keypair
EVP_PKEY* generate_ephemeral_key() {
    // --- PHASE 1: Parameter Generation (Curve selection) ---
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

    // --- PHASE 2: Key Pair Generation ---
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

vector<uint8_t> generate_nonce(size_t length) {
    vector<uint8_t> nonce(length);
    if (RAND_bytes(nonce.data(), length) != 1) {
        cerr << "Critical error: unable to generate entropy for nonce." << endl;
        exit(EXIT_FAILURE); 
    }
    return nonce;
}

// Converts an EVP_PKEY object into a raw byte vector for network transmission
vector<uint8_t> serialize_pubkey(EVP_PKEY* pkey) {
    unsigned char* buf = nullptr;
    int len = i2d_PUBKEY(pkey, &buf);
    vector<uint8_t> result(buf, buf + len);
    OPENSSL_free(buf);
    return result;
}

// Converts a raw byte vector received from the network back into an EVP_PKEY object
EVP_PKEY* deserialize_pubkey(const vector<uint8_t>& pubkey_bytes) {
    const unsigned char* ptr = pubkey_bytes.data();
    return d2i_PUBKEY(NULL, &ptr, pubkey_bytes.size());
}

vector<uint8_t> sign_data(const vector<uint8_t>& data, EVP_PKEY* priv_key) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    // Check if context creation was successful
    if (!ctx) {
        cerr << "Error creating message digest context" << endl;
        return {};
    }
    size_t sig_len;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv_key) <= 0) {
        // Error handling logic
        cerr << "Error initializing signature operation" << endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    if (EVP_DigestSign(ctx, NULL, &sig_len, data.data(), data.size()) <= 0) {
        // Error handling logic
        cerr << "Error determining signature length" << endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    vector<uint8_t> signature(sig_len);
    if (EVP_DigestSign(ctx, signature.data(), &sig_len, data.data(), data.size()) <= 0) {
        // Error handling logic
        cerr << "Error generating signature" << endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    EVP_MD_CTX_free(ctx);
    return signature;
}

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

bool derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pub_key, vector<uint8_t>& out_secret) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) return false;

    if (EVP_PKEY_derive_init(ctx) <= 0) return false;
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0) return false;

    size_t secret_len;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) return false;

    out_secret.resize(secret_len);
    if (EVP_PKEY_derive(ctx, out_secret.data(), &secret_len) <= 0) return false;

    EVP_PKEY_CTX_free(ctx);
    return true;
}