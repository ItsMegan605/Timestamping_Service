#include "../header_files/common.h"
#include "../header_files/crypto.h"
#include "../header_files/protocol.h"
#include "../header_files/database.h"

#include <iostream>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>

using namespace std;

// TODO: (Database) The UserDatabase instance should ideally be global or passed by reference to threads.
// UserDatabase db;


void handle_client(int client_socket) {
    // TODO: (X.509 Architecture) The server should also load its X.509 certificate 
    // (e.g., "server_cert.pem") to send it to the client during the handshake.
    
    // Load the server's long-term private key for signing the transcript
    EVP_PKEY* server_conn_priv = load_private_key("../keys/server_conn_priv.pem");
    if (!server_conn_priv) {
        close(client_socket);
        return;
    }

    // ---------- receiving client hello ----------
    // Receive the Client Hello message
    vector<uint8_t> client_hello_payload;
    if (!recv_message(client_socket, client_hello_payload)) {
        EVP_PKEY_free(server_conn_priv);
        close(client_socket);
        return;
    }

    // Unpack Epub_C and Nc
    vector<uint8_t> epub_c, nc;
    if (!unpack_client_hello(client_hello_payload, epub_c, nc)) {
        EVP_PKEY_free(server_conn_priv);
        close(client_socket);
        return;
    }


    // ----- server hello generation -------
    // Generate Server Nonce (Ns) and ephemeral ECDH key pair
    vector<uint8_t> ns = generate_nonce(NONCE_SIZE);
    EVP_PKEY* server_eph_key = generate_ephemeral_key();

    if (!server_eph_key) {
        cerr << "error while generating ephimeral key" << endl;
        EVP_PKEY_free(server_conn_priv);
        close(client_socket);
        return;
    }

    vector<uint8_t> epub_s = serialize_pubkey(server_eph_key);

    // Build the transcript to be signed: (Epub_C || Nc || Ns || Epub_S)
    vector<uint8_t> transcript;
    transcript.insert(transcript.end(), epub_c.begin(), epub_c.end());
    transcript.insert(transcript.end(), nc.begin(), nc.end());
    transcript.insert(transcript.end(), ns.begin(), ns.end());
    transcript.insert(transcript.end(), epub_s.begin(), epub_s.end());

    // Sign the transcript to authenticate the server to the client
    vector<uint8_t> signature = sign_data(transcript, server_conn_priv);
    
    // TODO: (Protocol) Modify pack_server_hello to include the server's X.509 certificate (in DER format) 
    // so the client can extract it and verify it using X509_verify_cert().
    
    // Pack and send the Server Hello message
    vector<uint8_t> server_hello_payload = pack_server_hello(epub_s, ns, signature);
    
    if (!send_message(client_socket, server_hello_payload)) {
        EVP_PKEY_free(server_conn_priv);
        EVP_PKEY_free(server_eph_key);
        close(client_socket);
        return;
    }

    // ----- shared secret calculation ------

    // Derive the ECDH Shared Secret
    vector<uint8_t> shared_secret;
    EVP_PKEY* peer_pub_key = deserialize_pubkey(epub_c);
    if (!peer_pub_key || !derive_shared_secret(server_eph_key, peer_pub_key, shared_secret)) {
        cerr << "Errore critico: impossibile derivare il segreto condiviso ECDH" << endl;
        if (peer_pub_key) EVP_PKEY_free(peer_pub_key);
        EVP_PKEY_free(server_conn_priv);
        EVP_PKEY_free(server_eph_key);
        close(client_socket);
        return;
    }
    cout << "[Server] ECDH Shared secret calculated successfully!" << endl;
    EVP_PKEY_free(peer_pub_key);
    
    
    // TODO: (Session Keys - HKDF)
    // 1. Invoke hkdf_extract_expand(shared_secret, nc, ns, aes_key, aes_iv).
    // 2. Securely erase shared_secret from memory (e.g., OPENSSL_cleanse) to ensure PFS.
    // 3. Initialize a local sequence number (uint64_t seq_num = 0) for AES-GCM anti-replay.

    // TODO: (Application Phase - Authentication)
    // 1. Wait for AuthRequest using a NEW recv_secure_message() (AES-GCM decryption + TAG check).
    // 2. Unpack AuthRequest.
    // 3. Hash the received password with the user's salt and compare it with the stored hash (db.authenticate()).
    // 4. Send AuthResponse via send_secure_message(). If authentication fails, close socket and return.

    // TODO: (Application Phase - Timestamp Service Loop)
    // while(recv_secure_message(client_socket, encrypted_cmd, aes_key, aes_iv, &seq_num)) {
    //     Extract command type.
    //     
    //     IF command == BALANCE:
    //         1. Fetch consumed and remaining timestamps from DB (db.get_balance()).
    //         2. Pack and send encrypted BalanceResponse.
    //
    //     IF command == TIMESTAMP:
    //         1. Check DB quota (db.consume_timestamp()) - make sure this is thread-safe (mutex).
    //         2. If quota exhausted, send encrypted QUOTA_EXHAUSTED Response.
    //         3. If quota > 0:
    //            a. Extract document hash from request.
    //            b. Get current system time (Unix timestamp).
    //            c. Concatenate (hash || time).
    //            d. Load the specific Timestamping private key ("server_ts_priv.pem").
    //            e. Sign the concatenation (EVP_DigestSign).
    //            f. Pack <hash, time, signature> and send encrypted TimestampResponse.
    // }

    // Cleanup resources
    // TODO: Consider using RAII (std::unique_ptr with custom deleters) for EVP_PKEY 
    // to avoid memory leaks if early returns occur in the logic above.
// Cleanup resources
    EVP_PKEY_free(server_conn_priv);
    EVP_PKEY_free(server_eph_key);
    close(client_socket);
}

int main() {

    // TODO: (Database) Load the user database from the JSON file into memory BEFORE accepting connections.
    // if (!db.load_from_file("data/users.json")) { return EXIT_FAILURE; }
    
    //opening of the connection
    int server_fd = setup_server(DEFAULT_PORT);
    if (server_fd < 0) return EXIT_FAILURE;
    
    cout << "[Server] Listening on port " << DEFAULT_PORT << "..." << endl;
    
    while (1) {
        struct sockaddr_in client_addr; 
        socklen_t addr_len = sizeof(client_addr);
        
        // Accept incoming connections and delegate them to a detached thread
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd >= 0) {
            thread client_thread(handle_client, client_fd);
            client_thread.detach(); 
        }
    }
    return 0;
}