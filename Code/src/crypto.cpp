/**
 * crypto.cpp - Implements all cryptographic operations using OpenSSL.

 */

#include "/home/megan/uni/FoC/project/Timestamping_Service/Code/header_files/crypto.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <iostream>

EVP_PKEY* generate_ephemeral_key() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    
    EVP_PKEY *ephemeral_key = NULL;
    EVP_PKEY_keygen(pctx, &ephemeral_key);
    EVP_PKEY_CTX_free(pctx);
    
    return ephemeral_key;
}

// Qui aggiungerai anche serialize_public_key, deserialize_public_key 
// e derive_shared_secret usando l'approccio mostrato prima.



