#include "../header_files/common.h"
#include "../header_files/crypto.h"
#include "../header_files/protocol.h"
#include "../header_files/interface.h"
#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std;

int main() {
//-----------------client preparation ----------------

// first. we eastablish the server connection
printBanner("[CLIENT] Server connection: please wait...", BOLD_MAGENTA);
    int sock = server_connection(IP_ADDRESS, DEFAULT_PORT);
    if (sock < 0) {
    cerr << "[CLIENT ERROR] Unable to connect to the server." << endl;
    return EXIT_FAILURE;
    }
    cout << "[CLIENT] TCP socket successfully established (FD: " << sock << ")." << endl;


    EVP_PKEY* server_conn_pub = load_public_key("../keys/server_conn_pub.pem");

    if (!server_conn_pub) {
        close(sock);
        return EXIT_FAILURE;
    }

    cout << "Preparing for hanshake..." << endl;

    // Generate Client Nonce (Nc) and ephemeral ECDH key pair
    vector<uint8_t> nc = generate_nonce(NONCE_SIZE);
    //Generate ephemeral ECDH key pair for Perfect Forward Secrecy (PFS)
    EVP_PKEY* client_eph_key = generate_ephemeral_key();

    if (!client_eph_key) {
        cerr << "Error while generating ephimeral key" << endl;
        EVP_PKEY_free(server_conn_pub);
        close(sock);
        return EXIT_FAILURE;
    }
    
    vector<uint8_t> epub_c = serialize_pubkey(client_eph_key);
    //at this point we have the nonce nc and the ephimeral keu client_eph_key
    //we have to send them as a message for the hello exchange 

//------------- hello message exchange ----------------------

printBanner("[CLIENT] Sending 'Client Hello' message to the server", BOLD_MAGENTA);
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

    cout << "Waiting for server's reply..." << endl;

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

//No KEM since we used diffie hellman on elliptic curves

//--------------------- identity verification and authentication ------------

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
    
EVP_PKEY_free(server_conn_pub);
// -------------- secret deriving ---------------

    // Derive the ECDH Shared Secret
    vector<uint8_t> shared_secret;
    EVP_PKEY* peer_pub_key = deserialize_pubkey(epub_s);
    
    if (!peer_pub_key || !derive_shared_secret(client_eph_key, peer_pub_key, shared_secret)) {
        cerr << "Critical error: impossible to derive shared secret" << endl;
        if (peer_pub_key) {
            EVP_PKEY_free(peer_pub_key);
        }
        
        EVP_PKEY_free(client_eph_key);
        close(sock); 
        return EXIT_FAILURE; 
    }
    
    cout << "[Client] ECDH Shared secret calculated successfully!" << endl; 
    EVP_PKEY_free(peer_pub_key);
    
    // Deallocazione della chiave effimera del client, il segreto è stato estratto
    EVP_PKEY_free(client_eph_key);

// -------------- key derivation function (KDF) ---------------

    vector<uint8_t> aes_key;
    vector<uint8_t> aes_iv;
    
    // 1. Chiamata alla HKDF per generare le chiavi AES
    if (!hkdf_extract_expand(shared_secret, nc, ns, aes_key, aes_iv)) {
        cerr << "Critical error: HKDF derivation failed" << endl;
        OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
        close(sock);
        return EXIT_FAILURE;
    }

    // 2. Pulizia del segreto matematico dalla RAM per Perfect Forward Secrecy
    OPENSSL_cleanse(shared_secret.data(), shared_secret.size());

    // Il canale è sicuro solo in questo momento
    printBanner("[CLIENT] Handshake completed! Secure channel active.", BOLD_GREEN);
    
    // Inizializzazione sequence number per prevenire Replay Attacks
    uint64_t seq_num = 0;
    
// -------------------------------------------------------------------------
//USER AUTHENTICATION IN SECURE CHANNEL (Module: crypto.cpp + protocol.cpp)
// -------------------------------------------------------------------------

printBanner("AUTHENTICATION: please insert your credentials", BOLD_YELLOW);
    //controlli su username e psw
    string username;
    string password;

    cout << "Insert Username: \n";
    cin >> username; 
    
    cout << "Insert Password: \n";
    cin >> password;


    if (username.empty() || password.empty()) {
        cerr << "Error: username and password must not be empty" << endl;
        close(sock);
        return EXIT_FAILURE;
    }

    AuthRequest auth_req;
    auth_req.username = username;
    auth_req.password = password;

    vector<uint8_t> auth_payload = pack_auth_request(auth_req);


    if (!send_secure_message(sock, auth_payload, aes_key, aes_iv, seq_num)) {
        cerr << "Error securely sending authentication request" << endl;
        OPENSSL_cleanse(&username[0], username.size());
        OPENSSL_cleanse(&password[0], password.size());
        close(sock);
        return EXIT_FAILURE;
    }

vector<uint8_t> auth_response_payload;
    if (!recv_secure_message(sock, auth_response_payload, aes_key, aes_iv, seq_num)) {
        cerr << "Error securely receiving authentication response (possible MitM or Replay Attack)" << endl;
        OPENSSL_cleanse(&username[0], username.size());
        OPENSSL_cleanse(&password[0], password.size());
        close(sock);
        return EXIT_FAILURE;
    }

    // 4. Spacchettamento risposta
    AuthResponse auth_res;
    if (unpack_auth_response(auth_response_payload, auth_res) != 1) {
        cerr << "Invalid authentication response format from server" << endl;
        OPENSSL_cleanse(&username[0], username.size());
        OPENSSL_cleanse(&password[0], password.size());
        close(sock);
        return EXIT_FAILURE;
    }

    // 5. Verifica esito del login
    if (auth_res.status != Status::OK) {
        cerr << "[CLIENT] Login failed: invalid credentials" << endl;
        OPENSSL_cleanse(&username[0], username.size());
        OPENSSL_cleanse(&password[0], password.size());
        close(sock);
        return EXIT_FAILURE;
    }

    // Pulizia delle credenziali in chiaro dalla memoria RAM
    OPENSSL_cleanse(&username[0], username.size());
    OPENSSL_cleanse(&password[0], password.size());

    printBanner("Login was succesful, welcome to the service!", BOLD_GREEN);
    

    // -------------------------------------------------------------------------
    // PHASE 6: APPLICATION LOOP - BALANCE & TIMESTAMP [SPECIFICATIONS]
    // -------------------------------------------------------------------------

        while(true) {
            homeMenu();
            string choice;
            cin >> choice;
            if ( choice == "balance") {
            //call balance function
            vector<uint8_t> balance = getUserBalance();
            
            } 
            else if (choice == "timestamp"){
                //call balance fucntion
                vector<uint8_t> timestamp = getUserTimestamp();
            }

            else if (choice == "verify") {
            //call verify function
            vector<uint8_t> verification = userVerification();
            } 

            else if (choice == "exit") {
            //call exit function

            printBanner("Thank you for using our service, see you soon!", BOLD_BLUE);
            close(sock);
            return EXIT_SUCCESS; 

            } else {
                printBanner("Command not recognised, try again.", BOLD_RED);
            }
        }
    
    // -------------------------------------------------------------------------
    // PHASE 7: TEARDOWN AND RESOURCE CLEANUP
    // -------------------------------------------------------------------------
    // Cleanup resources before exiting
    
    close(sock);
    return EXIT_SUCCESS;
    
}