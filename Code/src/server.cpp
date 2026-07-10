#include "../header_files/common.h"
#include "../header_files/crypto.h"
#include "../header_files/protocol.h"
#include "../header_files/database.h"

#include <iostream>
#include <thread>
#include <vector>

// Header di sistema necessari per i socket e EXIT_FAILURE
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>

using namespace std;

void handle_client(int client_socket) {
    // 1. Riceve ClientHello (Nc) via recv_message() 
    
    // 2. Genera il proprio Nonce (Ns) e la propria chiave effimera (Epub_S)
    EVP_PKEY* server_eph_key = generate_ephemeral_key();
    
    // 3. Firma (Nc || Ns || Epub_S) con privKc caricata all'avvio (sign_data)
    
    // 4. Invia ServerHello (Ns, Epub_S, Firma) al client tramite send_message()
    
    // 5. Riceve ClientKeyExchange (Epub_C) tramite recv_message()
    
    // 6. Calcola derive_shared_secret(...) ed esegue HKDF per ottenere chiavi AES 
    
    // 7. Ora il canale sicuro è stabilito. Entra nel loop di servizio: 
    //    - Ricevi comandi cifrati con AES-GCM (usa recv_message + aes_gcm_decrypt)
    //    - Il primo byte del payload decifrato è il Command (AUTH, TIMESTAMP, BALANCE)
    //    - Gestisci ogni comando, usando il database per autenticare e gestire i timestamp.
    //    - Invia risposte cifrate con send_message + aes_gcm_encrypt
}

int main() {
    // Carica i key pair (pubKc, privKc, pubKts, privKts) dai PEM all'avvio
    // Carica il database users.json all'avvio
    // Usa DEFAULT_PORT definito in common.h
    int server_fd = setup_server(DEFAULT_PORT);
    if (server_fd < 0) return EXIT_FAILURE;
    
    printf("[Server] Listening on port %d...\n", DEFAULT_PORT);
    
    while (1) {
        struct sockaddr_in client_addr; 
        socklen_t addr_len = sizeof(client_addr);
        
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd >= 0) {
            // Delega la gestione crittografica e di I/O a un thread worker indipendente.
            std::thread client_thread(handle_client, client_fd);
            client_thread.detach(); 
        }
    }
    return 0;
}