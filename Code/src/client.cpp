#include "../header_files/common.h"
#include "../header_files/crypto.h"
#include "../header_files/protocol.h"
#include <iostream>
#include <unistd.h>
#include <cstdlib>

using namespace std;

int main() {
    int sock = server_connection(IP_ADDRESS, DEFAULT_PORT);
    if (sock < 0) return EXIT_FAILURE;
    
//-----------------client preparation ----------------
    
    // TODO: (X.509 Architecture) Do not load the raw public key directly.
    // 1. Create an X509_STORE (X509_STORE_new).
    // 2. Load your root CA certificate (e.g., "cacert.pem") into the store (X509_STORE_add_cert).
    // 3. Set up a verification context (X509_STORE_CTX_new).
    
    EVP_PKEY* server_conn_pub = load_public_key("../keys/server_conn_pub.pem");
    // TODO: This 'server_conn_pub' variable should be dynamically extracted from the 
    // server certificate you receive in the Server Hello using X509_get_pubkey().
    
    if (!server_conn_pub) {
        close(sock);
        return EXIT_FAILURE;
    }

    // Generate Client Nonce (Nc) and ephemeral ECDH key pair
    vector<uint8_t> nc = generate_nonce(NONCE_SIZE);
    EVP_PKEY* client_eph_key = generate_ephemeral_key();

    if (!client_eph_key) {
        cerr << "Errore nella generazione della chiave effimera" << endl;
        EVP_PKEY_free(server_conn_pub);
        close(sock);
        return EXIT_FAILURE;
    }
    
    vector<uint8_t> epub_c = serialize_pubkey(client_eph_key);


    //------------- hello message exchange ----------------------

    // Pack and send the Client Hello message
    vector<uint8_t> client_hello_payload = pack_client_hello(epub_c, nc);
    
    //waits for the server's reply
    if (!send_message(sock, client_hello_payload)) {
        cerr << "Error sending Client Hello" << endl;
        EVP_PKEY_free(server_conn_pub);
        EVP_PKEY_free(client_eph_key);
        close(sock);
        return EXIT_FAILURE;
    }

    // Wait for the Server Hello response
    vector<uint8_t> server_hello_payload;
    if (!recv_message(sock, server_hello_payload)) { 
        cerr << "Error receiving from server" << endl; 
        EVP_PKEY_free(server_conn_pub);
        EVP_PKEY_free(client_eph_key);
        close(sock);
        return EXIT_FAILURE; 
    }

    // Unpack the Server Hello to extract Epub_S, Ns, and the signature
    vector<uint8_t> epub_s, ns, signature;
    // TODO: (Protocol) Modify unpack_server_hello to also extract the Server Certificate (in DER format).
    if (!unpack_server_hello(server_hello_payload, epub_s, ns, signature)) {
        cerr << "Error parsing Server Hello" << endl;
        EVP_PKEY_free(server_conn_pub);
        EVP_PKEY_free(client_eph_key);
        close(sock);
        return EXIT_FAILURE;
    }


//--------------------- verification and authentication ------------
    
    // TODO: (Certificate Validation) 
    // 1. Deserialize the server certificate (d2i_X509).
    // 2. Validate the certificate using X509_verify_cert() against the X509_STORE created at the beginning.
    // 3. If invalid, abort due to possible MitM.
    // 4. Extract the public key from the valid certificate (X509_get_pubkey) and use it instead 
    //    of the hardcoded file-loaded one to verify the signature below.

    // Reconstruct the exact transcript signed by the server: (Epub_C || Nc || Ns || Epub_S)
    vector<uint8_t> transcript;
    transcript.insert(transcript.end(), epub_c.begin(), epub_c.end());
    transcript.insert(transcript.end(), nc.begin(), nc.end());
    transcript.insert(transcript.end(), ns.begin(), ns.end());
    transcript.insert(transcript.end(), epub_s.begin(), epub_s.end());

    // Verify the server's identity using its long-term public key
    if (!verify_signature(transcript, signature, server_conn_pub)) {
        cerr << "FATAL: Invalid server signature. Possible MitM attack." << endl;
        EVP_PKEY_free(server_conn_pub);
        EVP_PKEY_free(client_eph_key);
        close(sock);
        return EXIT_FAILURE;
    }
    
    cout << "[Client] Handshake verified successfully!" << endl;


// -------------- secret deriving ---------------

    // Derive the ECDH Shared Secret
    vector<uint8_t> shared_secret;
    EVP_PKEY* peer_pub_key = deserialize_pubkey(epub_s);
    
    if (!peer_pub_key || !derive_shared_secret(client_eph_key, peer_pub_key, shared_secret)) {
        cerr << "Critical error: impossible to derive shared secret" << endl;
        if (peer_pub_key) {
            EVP_PKEY_free(peer_pub_key);
        }
        
        EVP_PKEY_free(server_conn_pub); 
        EVP_PKEY_free(client_eph_key);
        
        close(sock); 
        return EXIT_FAILURE; 
    }
    
    cout << "[Client] ECDH Shared secret calculated successfully!" << endl; 
    EVP_PKEY_free(peer_pub_key);

    // TODO: (Session Keys - HKDF)
    // 1. Invoke hkdf_extract_expand(shared_secret, nc, ns, aes_key, aes_iv).
    // 2. Immediately destroy shared_secret from memory for PFS (e.g., OPENSSL_cleanse).
    // 3. Initialize a local sequence number to 0 (uint64_t seq_num = 0) to prevent Replay Attacks.

    // TODO: (Application Phase - Authentication)
    // 1. Request user input (username and password).
    // 2. Create the AuthRequest struct and serialize it with pack_auth_request().
    // 3. Send the payload using a NEW send_secure_message() function 
    //    that encrypts with AES-256-GCM using aes_key, aes_iv + seq_num, and appends the TAG for integrity.
    // 4. Increment seq_num.
    // 5. Wait for AuthResponse via recv_secure_message() (which decrypts and checks the TAG).
    // 6. Verify the Status (OK or AUTH_FAILED).

    // TODO: (Application Phase - Timestamp Service)
    // If authentication succeeds, start a loop/menu:
    // Option 1: Balance() -> Send encrypted command, receive and print (nc, nr).
    // Option 2: Timestamp(file) -> 
    //    - Calculate the local hash of the file (sha256_file).
    //    - Send the encrypted hash to the server.
    //    - Receive the encrypted tuple <hash, time, signature>.
    //    - Save the tuple to a file.
    // Option 3: Verify Timestamp -> 
    //    - Load the specific timestamping key/certificate (server_ts_pub.pem).
    //    - Use EVP_DigestVerify to validate that the received signature is correct for the string (hash || time).

    // Cleanup resources before exiting
    // TODO: Apply RAII or ensure you free the added resources (X509_STORE, X509, etc.)

    
    // Cleanup resources before exiting
    EVP_PKEY_free(server_conn_pub);
    EVP_PKEY_free(client_eph_key);
    close(sock);
    
    return EXIT_SUCCESS;
    
}