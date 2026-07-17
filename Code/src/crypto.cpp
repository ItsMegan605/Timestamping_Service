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

// HKDF implementation (manual using HMAC-SHA256)
/*
 internal helper : HMAC-SHA256 of data with a given key
 returns the 32-byte HMAC result
*/
static array<uint8_t, 32> hmac_sha256(const vector<uint8_t>& key, const vector<uint8_t>& data) {
    array<uint8_t, 32> result;
    unsigned int result_len = 0;   

    // openSSL's HMAC function: HMAC(evp_md, key, key_len, data, data_len, out, out_len)
    if (HMAC (EVP_sha256(), key.data(), key.size(), data.data(), data.size(), result.data(), &result_len) == NULL) {
        cerr << "ERROR: HMAC-SHA256 failed" << endl;
        result.fill(0); // zero out on error
        return result;
    }

    if (result_len != 32) {
        cerr << "WARNING : unexpected HMAC length: " << result_len << endl;
    }

    return result;
}       

/*
 HKDF-extract: computes PRK = HMAC-SHA256(salt, IKM)
 @param salt - the salt value (client nonce || server nonce
 @param ikm - the input keying material (ECDH shared secret)
 @return PRK - the pseudorandom key (32 bytes)
*/
static array<uint8_t, 32> hkdf_extract(const vector<uint8_t>& salt, const vector<uint8_t>& ikm) {
    // if salt is empty, HMAC uses a zero-length salt (standard behavior of HKDF)
    // our salt is alway 64 bytes (32 bytes client nonce + 32 bytes server nonce)
    return hmac_sha256(salt, ikm);
}

/*
 HKDF-expand: expands the PRK into the required output length
 @param prk - the pseudorandom key from hkdf_extract
 @param info - context specific info string ("e.g tss_session_key")
 @param out_len - desired output length in bytes 
 @return expanded key material
*/
static vector<uint8_t> hkdf_expand(const array<uint8_t, 32>& prk, const string& info, size_t out_len) {
    vector<uint8_t> output; 
    output.reserve(out_len);

    vector<uint8_t> T_prev; // T(i-1) 
    uint8_t counter = 1;

    // loop until we have enough bytes
    while (output.size() < out_len) {
        // build the input for  HMAC: (T(i-1) || info || counter)
        vector<uint8_t> input;
        input.insert(input.end(), T_prev.begin(), T_prev.end());    
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);

        // compute T(i) = HMAC-SHA256(PRK, input)
        array<uint8_t, 32> T_i = hmac_sha256(vector<uint8_t>(prk.begin(), prk.end()), input);

        // append T(i) to the output
        output.insert(output.end(), T_i.begin(), T_i.end());

        // store T(i) as T_prev for the next iteration
        T_prev.assign(T_i.begin(), T_i.end());
        counter++;

        // HKDF spec: counter should not overflow (max 255 iterations)
        if (counter == 0) {
            cerr << "ERROR: HKDF-Expand counter overflow" << endl;
            break;
        }
    }

    // truncate to the desired length
    output.resize(out_len);
    return output;
}

/*
 public HKDF function: combines extract and expand to derive key material from ECDH shared secret
*/
bool hkdf_extract_expand(const vector<uint8_t>& shared_secret, 
                         const vector<uint8_t>& client_nonce,
                         const vector<uint8_t>& server_nonce, 
                         vector<uint8_t>& out_enc_key,
                         vector<uint8_t>& out_iv) {

    // validate input
    if (shared_secret.empty()) {
        cerr << "ERROR: shared secret is empty" << endl;
        return false;
    }

    if (client_nonce.size() != NONCE_SIZE || server_nonce.size() != NONCE_SIZE) {
        cerr << "ERROR: nonces must be " << NONCE_SIZE << " bytes " << endl;
        return false;
    }

    // build the salt as client_nonce || server_nonce
    vector<uint8_t> salt;
    salt.reserve(NONCE_SIZE * 2);
    salt.insert(salt.end(), client_nonce.begin(), client_nonce.end());
    salt.insert(salt.end(), server_nonce.begin(), server_nonce.end());

    // HKDF-Extract
    array<uint8_t, 32> prk = hkdf_extract(salt, shared_secret);

    // HKDF-Expand with info = "tss_session_key"
    // total output length = 32 bytes (AES key) + 12 bytes (IV) = 44 bytes
    const size_t AES_KEY_LEN = 32;
    const size_t IV_LEN = 12;
    const size_t TOTAL_LEN = AES_KEY_LEN + IV_LEN;
    const string info = "tss_session_key";

    vector<uint8_t> expanded = hkdf_expand(prk, info, TOTAL_LEN);

    if (expanded.size() != TOTAL_LEN) {
        cerr << "ERROR: HKDF-Expand produced unexpected length" << endl;
        return false;
    }

    // split the output into key and IV
    out_enc_key.assign(expanded.begin(), expanded.begin() + AES_KEY_LEN);
    out_iv.assign(expanded.begin() + AES_KEY_LEN, expanded.end());

    // validate lengths
    if (out_enc_key.size() != AES_KEY_LEN || out_iv.size() != IV_LEN) {
        cerr << "ERROR: HKDF output split failed" << endl;
        return false;
    }

    return true; // success
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