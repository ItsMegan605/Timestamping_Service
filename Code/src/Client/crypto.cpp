/**
 * crypto.cpp - Implements all cryptographic operations using OpenSSL.
 * 
 * TODO: sha256_file():
 *   - Open file, read in chunks, use EVP_DigestUpdate(), finalize.
 * 
 * TODO: sha256_data():
 *   - Similar but on a memory buffer.
 * 
 * TODO: load_public_key():
 *   - Use PEM_read_PUBKEY() (or PEM_read_RSAPublicKey for RSA).
 *   - Return EVP_PKEY* (caller must free).
 * 
 * TODO: load_private_key():
 *   - Use PEM_read_PrivateKey() (passphrase = nullptr for now).
 * 
 * TODO: sign_timestamp():
 *   - Concatenate hash (32 bytes) and timestamp (8 bytes) into a single buffer.
 *   - Use EVP_DigestSignInit with SHA-256, EVP_DigestSignUpdate, EVP_DigestSignFinal.
 *   - Return signature as vector<uint8_t>.
 * 
 * TODO: verify_timestamp():
 *   - Same but use EVP_DigestVerifyInit/Update/Final.
 * 
 * TODO: create_tls_client_ctx():
 *   - Use TLS_client_method(), set verify mode to SSL_VERIFY_PEER.
 *   - Load CA certificate for server verification.
 *   - Force TLS 1.3 (or ECDHE ciphers if using 1.2).
 * 
 * TODO: create_tls_server_ctx():
 *   - Use TLS_server_method(), load certificate and private key.
 *   - Set session caching off for simplicity.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

int generate_handshake_ephimeral () {
    //diffici hellman elliètic curve generation
}

int export_public_key () {

}

int nonce_generation() {
    
}


