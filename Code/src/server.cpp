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

EVP_PKEY* ts_privk = nullptr; // Server's timestamping private key

void handle_client(int client_socket) {

    printBanner("[SERVER] New client connection request received.", BOLD_MAGENTA);
    
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
    
    if (!hkdf_extract_expand(shared_secret, nc, ns, aes_key)) {
        cerr << "Critical error: HKDF derivation failed" << endl;
        OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
        close(client_socket);
        return;
    }

    OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
    printBanner("[SERVER] Handshake completed! Secure channel active.", BOLD_GREEN);
    
    uint64_t send_seq_num = 0;
    uint64_t recv_seq_num = 0;
    
//----------------------- authentication phase -----------------------
    vector<uint8_t> authentication;
    int max_tries = 3;
    bool is_authenticated = false;
    AuthRequest authRequest;

    while(max_tries > 0) {
        if(!recv_secure_message(client_socket, authentication, aes_key, recv_seq_num)) {
            cerr << "[SERVER ERROR] Error securely receiving authentication request" << endl;
            close(client_socket);
            return;
        }

        //AuthRequest authRequest;
        if(unpack_auth_request(authentication, authRequest) != 1) {
            cerr << "Error with the request format" << endl;
            close(client_socket);
            return;
        }

        AuthResponse authResponse;
        is_authenticated = db.authenticate(authRequest.username, authRequest.password);

        if(is_authenticated){
            printBanner("Authentication succesful!", BOLD_GREEN);
            authResponse.status = Status::OK;
        } else {
            printBanner("Authentication failed", BOLD_RED);
            authResponse.status = Status::AUTH_FAILED;
            max_tries--;
        }

        vector<uint8_t> authResponsePayload = pack_auth_response(authResponse);
        
        if(!send_secure_message(client_socket, authResponsePayload, aes_key, send_seq_num)) {
            cerr << "SERVER ERROR securely answering the request!!" << endl;
            close(client_socket);
            return;
        }

        if (is_authenticated) {
            break;
        }
    }

    if (!is_authenticated) {
        cerr << "[SERVER] User failed to authenticate after 3 tries. Closing connection." << endl;
        close(client_socket);
        return;
    }
    // =========================================================================
    // APPLICATION LOOP (Balance, Timestamp, Exit)
    // =========================================================================

    // per le print colorate:
    /*
    * cout << BOLD_YELLOW << " [SERVER] \n" < RESET << "white msg \n";
    */
    while (true) {
        vector<uint8_t> encrypted_cmd;
        
        if (!recv_secure_message(client_socket, encrypted_cmd, aes_key, recv_seq_num)) {
            cout << "[SERVER] Client disconnected or secure channel error." << endl;
            break;
        }

        if (encrypted_cmd.empty()) continue;

        char command_type = static_cast<char>(encrypted_cmd[0]);

        if (command_type == 'B') { 
            cout << BOLD_PURPLE << "[SERVER] Received BALANCE request from user: " << authRequest.username << RESET << endl;
            
            BalanceResponse res;
            if (db.get_balance(authRequest.username, res.info)) {
                res.status = Status::OK;
            } else {
                res.status = Status::INTERNAL_ERROR;
            }

            vector<uint8_t> balance_payload = pack_balance_response(res);

            if (!send_secure_message(client_socket, balance_payload, aes_key, send_seq_num)) {
                cerr << "[SERVER ERROR] Impossible to send balance response" << endl;
                break;
            }
            cout << BOLD_GREEN << "[SERVER] BALANCE response successfully sent to the client." << RESET << endl;
        }
        else if (command_type == 'T') { 
            cout << BOLD_YELLOW << "[SERVER] Received TIMESTAMP request from user: " << authRequest.username << RESET << endl;
            
            if (encrypted_cmd.size() < 1 + 32) {
                cerr << BOLD_RED << "[SERVER ERROR] Invalid timestamp request length" << RESET << endl;
                break;
            }
            
            TimestampRequest ts_req;
            memcpy(ts_req.hash.data(), encrypted_cmd.data() + 1, 32);
                    
            TimestampResponse ts_res;
            ts_res.hash = ts_req.hash;
                    
            TimestampInfo info;
            
            if (!db.get_balance(authRequest.username, info) || info.remaining == 0) {
                ts_res.status = Status::QUOTA_EXHAUSTED;
                ts_res.timestamp = 0;
                ts_res.signature.clear();
                cout << BOLD_ORANGE << "[SERVER] Warning: user " << authRequest.username << " has exhausted their credits!" << endl;
            } else {
                ts_res.timestamp = static_cast<uint64_t>(time(nullptr)); 
            
                vector<uint8_t> signed_data(40);
                memcpy(signed_data.data(), ts_req.hash.data(), 32);
                uint64_t ts_net = htobe64(ts_res.timestamp);
                memcpy(signed_data.data() + 32, &ts_net, 8);
            
                ts_res.signature = sign_data(signed_data, ts_privk);
                
                if (ts_res.signature.empty()) {
                    ts_res.status = Status::INTERNAL_ERROR;
                    cerr << "[SERVER ERROR] Error during cryptographic signing!" << endl;
                } else {
                    db.consume_timestamp(authRequest.username);
                    ts_res.status = Status::OK;
                    cout << "[SERVER] Cryptographic signature generated. Credits deducted for user " << authRequest.username << "." << endl;
                }
            }

            vector<uint8_t> ts_response_payload = pack_timestamp_response(ts_res);
            if (!send_secure_message(client_socket, ts_response_payload, aes_key, send_seq_num)) {
                cerr << "[SERVER ERROR] Impossible to send timestamp response" << endl;
                break;
            }
            // Add this line to confirm the transmission
            cout << "[SERVER] TIMESTAMP response encrypted and successfully sent." << endl;
        }
        else if (command_type == 'E') { 
            cout << "[SERVER] Received session close request from user." << endl;
            break;
        }
    }

    close(client_socket);
}

// --------------------- mian code --------------------------------------

void threadListener (int port) {
    int server_fd = setup_server(port);
    if (server_fd < 0) 
        return;
    
    cout << BOLD_TEAL << "[Server] Listening on port " << port << RESET << endl;
    
    while (1) {
        struct sockaddr_in client_addr; 
        socklen_t addr_len = sizeof(client_addr);
        
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        
        if (client_fd >= 0) {
            thread(handle_client, client_fd).detach();
        }
    }
}
int main() {

    if (!db.load_from_file("../data/users.json")) {
        cerr << "[SERVER ERROR] Impossible to upload the users" << endl;
        return EXIT_FAILURE;
    }

    ts_privk = load_private_key("../keys/server_ts_priv.pem");
    if (!ts_privk) {
        cerr << "[SERVER ERROR] Failed to load timestamp signing key" << endl;
        return EXIT_FAILURE;
    }   
    
    jthread th_listener(threadListener, DEFAULT_PORT);
    return EXIT_SUCCESS;

}