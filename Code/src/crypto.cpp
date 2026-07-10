#include "../header_files/crypto.h"
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <cstdint>
#include <cstdlib>

EVP_PKEY* generate_ephemeral_key() {
    // --- PHASE 1: Parameter Generation  ---
    EVP_PKEY* dh_params = NULL;
    EVP_PKEY_CTX* ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    
    if (!ctx_params) {
        std::cerr << "Error creating parameter context" << std::endl;
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
        std::cerr << "Error creating key context" << std::endl;
        EVP_PKEY_free(dh_params);
        return NULL;
    }

    EVP_PKEY_keygen_init(ctx_key);
    EVP_PKEY_keygen(ctx_key, &ephemeral_key);
    
    EVP_PKEY_CTX_free(ctx_key);

    // We no longer need the parameters in this form once the key is generated
    EVP_PKEY_free(dh_params);

    return ephemeral_key;
}

std::vector<uint8_t> generate_nonce(size_t length) {
    std::vector<uint8_t> nonce(length);
    
    // RAND_bytes restituisce 1 in caso di successo, 0 o -1 in caso di errore
    if (RAND_bytes(nonce.data(), length) != 1) {
        std::cerr << "Errore critico: impossibile generare entropia per il nonce." << std::endl;
        exit(EXIT_FAILURE); 
    }
    
    return nonce;
}

// ================================================================
// TODO: Implement all other functions declared in crypto.h
// ================================================================
// - sha256_file / sha256_data        (use EVP_Digest)
// - load_public_key / load_private_key  (use PEM_read_*)
// - derive_shared_secret             (use EVP_PKEY_derive)
// - hkdf_extract_expand              (use EVP_KDF or manual HMAC)
// - aes_gcm_encrypt / decrypt        (use EVP_CipherInit_ex with AES-256-GCM)
// - sign_data / verify_signature     (use EVP_Sign* / EVP_Verify*)
// - sign_timestamp / verify_timestamp (same, but convert timestamp to big-endian)
// ================================================================