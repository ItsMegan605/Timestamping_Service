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
    
    // Load the server's public key to verify its signature later
    EVP_PKEY* server_conn_pub = load_public_key("../keys/server_conn_pub.pem");
    if (!server_conn_pub) {
        close(sock);
        return EXIT_FAILURE;
    }

    // Generate Client Nonce (Nc) and ephemeral ECDH key pair
    vector<uint8_t> nc = generate_nonce(NONCE_SIZE);
    EVP_PKEY* client_eph_key = generate_ephemeral_key();
    vector<uint8_t> epub_c = serialize_pubkey(client_eph_key);

    // Pack and send the Client Hello message
    vector<uint8_t> client_hello_payload = pack_client_hello(epub_c, nc);
    
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
    if (!unpack_server_hello(server_hello_payload, epub_s, ns, signature)) {
        cerr << "Error parsing Server Hello" << endl;
        EVP_PKEY_free(server_conn_pub);
        EVP_PKEY_free(client_eph_key);
        close(sock);
        return EXIT_FAILURE;
    }

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

    // Derive the ECDH Shared Secret
    vector<uint8_t> shared_secret;
    EVP_PKEY* peer_pub_key = deserialize_pubkey(epub_s);
    
    if (peer_pub_key) {
        if (derive_shared_secret(client_eph_key, peer_pub_key, shared_secret)) {
            cout << "[Client] ECDH Shared secret calculated successfully!" << endl;
        }
        EVP_PKEY_free(peer_pub_key);
    }

    // Cleanup resources before exiting
    EVP_PKEY_free(server_conn_pub);
    EVP_PKEY_free(client_eph_key);
    close(sock);
    
    return EXIT_SUCCESS;
}