#include "../header_files/common.h"
#include "../header_files/crypto.h"
#include "../header_files/protocol.h"
#include "../header_files/database.h"
#include "../header_files/interface.h"

#include <iostream>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std;
UserDatabase db;

void handle_client(int client_socket) {

    printBanner("[SERVER] New client connection established.", BOLD_MAGENTA);
    
    // Load the server's long-term private key for signing the transcript
    EVP_PKEY* server_conn_priv = load_private_key("../keys/server_conn_priv.pem");
    if (!server_conn_priv) {
        close(client_socket);
        return;
    }

    // ---------- receiving client hello ----------
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

    printBanner("[SERVER] 'Client Hello' received. Preparing reply...", BOLD_MAGENTA);

    // ----- server hello generation -------
    vector<uint8_t> ns = generate_nonce(NONCE_SIZE);
    EVP_PKEY* server_eph_key = generate_ephemeral_key();

    if (!server_eph_key) {
        cerr << "error while generating ephemeral key" << endl;
        EVP_PKEY_free(server_conn_priv);
        close(client_socket);
        return;
    }

    vector<uint8_t> epub_s = serialize_pubkey(server_eph_key);

    // Build the transcript to be signed
    vector<uint8_t> transcript;
    transcript.insert(transcript.end(), epub_c.begin(), epub_c.end());
    transcript.insert(transcript.end(), nc.begin(), nc.end());
    transcript.insert(transcript.end(), ns.begin(), ns.end());
    transcript.insert(transcript.end(), epub_s.begin(), epub_s.end());

    // Sign the transcript
    vector<uint8_t> signature = sign_data(transcript, server_conn_priv);
    
    // Deallocazione UNICA della chiave privata a lungo termine
    EVP_PKEY_free(server_conn_priv);
    
    printBanner("[SERVER] Sending 'Server Hello' message", BOLD_MAGENTA);
    
    vector<uint8_t> server_hello_payload = pack_server_hello(epub_s, ns, signature);
    
    if (!send_message(client_socket, server_hello_payload)) {
        EVP_PKEY_free(server_eph_key); // Nessun double free qui
        close(client_socket);
        return;
    }

    // ----- shared secret calculation ------
    vector<uint8_t> shared_secret;
    EVP_PKEY* peer_pub_key = deserialize_pubkey(epub_c);
    
    if (!peer_pub_key || !derive_shared_secret(server_eph_key, peer_pub_key, shared_secret)) {
        cerr << "Critical error: impossible to derive ECDH shared secret" << endl;        
        if (peer_pub_key) EVP_PKEY_free(peer_pub_key);
        EVP_PKEY_free(server_eph_key); // Nessun double free qui
        close(client_socket);
        return;
    }
    
    cout << "[Server] ECDH Shared secret calculated successfully!" << endl;
    
    // Deallocazione UNICA delle chiavi effimere
    EVP_PKEY_free(peer_pub_key);
    EVP_PKEY_free(server_eph_key);
    
// -------------- key derivation function (KDF) ---------------
    
    vector<uint8_t> aes_key;
    vector<uint8_t> aes_iv;
    
    if (!hkdf_extract_expand(shared_secret, nc, ns, aes_key, aes_iv)) {
        cerr << "Critical error: HKDF derivation failed" << endl;
        OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
        close(client_socket);
        return;
    }

    OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
    printBanner("[SERVER] Handshake completed! Secure channel active.", BOLD_GREEN);
    
    uint64_t seq_num = 0;
    
//----------------------- authentication phase -----------------------
    vector<uint8_t> authentication;
    // 1. Ricezione sicura delle credenziali
    if(!recv_secure_message(client_socket, authentication, aes_key, aes_iv, seq_num)) {
        cerr << "[SERVER ERROR] Error securely receiving authentication request" << endl;
        close(client_socket);
        return;
    }

    AuthRequest authRequest;
    if(unpack_auth_request(authentication, authRequest) != 1) {
        cerr << "Error with the request format" << endl;
        close(client_socket);
        return;
    }

    AuthResponse authResponse;
    if(db.authenticate(authRequest.username, authRequest.password)){
        printBanner("Authentication succesful!", BOLD_GREEN);
        authResponse.status= Status::OK;
    } else {
        printBanner("Authentication failed", BOLD_RED);
        authResponse.status = Status::AUTH_FAILED;
    }

    vector<uint8_t> authResponsePayload = pack_auth_response(authResponse);
    
    // 2. Invio sicuro della risposta 
    if(!send_secure_message(client_socket, authResponsePayload, aes_key, aes_iv, seq_num)) {
        cerr << "SERVER ERROR securely answering the request!!" << endl;
        return;
    }

    while (true) {
        vector<uint8_t> encrypted_cmd;
        
        // 1. Securely wait for the next command from the client
        if (!recv_secure_message(client_socket, encrypted_cmd, aes_key, aes_iv, seq_num)) {
            cout << "[SERVER] Client disconnected or secure channel error." << endl;
            break;
        }

        if (encrypted_cmd.empty()) continue;

        // 2. Read the command type (e.g., the first byte sent by the client)
        char command_type = static_cast<char>(encrypted_cmd[0]);

        if (command_type == 'B') { 
            BalanceResponse res;
            
            // Interroghiamo il database usando l'username dell'utente autenticato in sessione
            if (db.get_balance(authRequest.username, res.info)) {
                res.status = Status::OK;
            } else {
                res.status = Status::INTERNAL_ERROR;
            }

            // Serializziamo la risposta
            vector<uint8_t> balance_payload = pack_balance_response(res);

            if (!send_secure_message(client_socket, balance_payload, aes_key, aes_iv, seq_num)) {
                cerr << "[SERVER ERROR] Impossible to send balance response" << endl;
                break;
            }
        }
        else if (command_type == 'T') { // Example for Timestamp
            // TODO: Handle timestamp consumption logic and digital signature
        }
        else if (command_type == 'E') { // Example for Exit / Graceful Logout
            cout << "[SERVER] Received session close request from user." << endl;
            break;
        }
    }
    // Cleanup resources
    // TODO: Consider using RAII (std::unique_ptr with custom deleters) for EVP_PKEY 
    // to avoid memory leaks if early returns occur in the logic above.
// Cleanup resources

    close(client_socket);
}



int main() {

    // Caricamento del database JSON prima di accettare connessioni
    if (!db.load_from_file("../data/users.json")) {
        cerr << "[SERVER ERROR] Impossibile caricare users.json" << endl;
        return EXIT_FAILURE;
    }
    
    //opening of the connection
    int server_fd = setup_server(DEFAULT_PORT);
    if (server_fd < 0) return EXIT_FAILURE;
    
    cout << "[Server] Listening on port " << DEFAULT_PORT << "..." << endl;
    
    while (1) {
        struct sockaddr_in client_addr; 
        socklen_t addr_len = sizeof(client_addr);
        
        // Accetta la connessione entrante
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        
        if (client_fd >= 0) {
            handle_client(client_fd);
        }
}

}