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

void handle_client(int client_socket) {
    // Load the server's long-term private key for signing the transcript
    EVP_PKEY* server_conn_priv = load_private_key("../keys/server_conn_priv.pem");
    if (!server_conn_priv) {
        close(client_socket);
        return;
    }

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

    // Generate Server Nonce (Ns) and ephemeral ECDH key pair
    vector<uint8_t> ns = generate_nonce(NONCE_SIZE);
    EVP_PKEY* server_eph_key = generate_ephemeral_key();
    vector<uint8_t> epub_s = serialize_pubkey(server_eph_key);

    // Build the transcript to be signed: (Epub_C || Nc || Ns || Epub_S)
    vector<uint8_t> transcript;
    transcript.insert(transcript.end(), epub_c.begin(), epub_c.end());
    transcript.insert(transcript.end(), nc.begin(), nc.end());
    transcript.insert(transcript.end(), ns.begin(), ns.end());
    transcript.insert(transcript.end(), epub_s.begin(), epub_s.end());

    // Sign the transcript to authenticate the server to the client
    vector<uint8_t> signature = sign_data(transcript, server_conn_priv);
    
    // Pack and send the Server Hello message
    vector<uint8_t> server_hello_payload = pack_server_hello(epub_s, ns, signature);
    
    if (!send_message(client_socket, server_hello_payload)) {
        EVP_PKEY_free(server_conn_priv);
        EVP_PKEY_free(server_eph_key);
        close(client_socket);
        return;
    }

    // Derive the ECDH Shared Secret
    vector<uint8_t> shared_secret;
    EVP_PKEY* peer_pub_key = deserialize_pubkey(epub_c);
    
    if (peer_pub_key) {
        if (derive_shared_secret(server_eph_key, peer_pub_key, shared_secret)) {
            cout << "[Server] ECDH Shared secret calculated successfully!" << endl;
        }
        EVP_PKEY_free(peer_pub_key);
    }

    // Cleanup resources
    EVP_PKEY_free(server_conn_priv);
    EVP_PKEY_free(server_eph_key);
    
    // (Next step: HKDF on shared_secret to generate AES keys)
}

int main() {
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