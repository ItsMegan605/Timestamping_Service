#include "../header_files/common.h"
#include "../header_files/crypto.h"

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
    // 1. Riceve ClientHello (Nc)
    
    // 2. Genera il proprio Nonce (Ns) e la propria chiave effimera (Epub_S)
    EVP_PKEY* server_eph_key = generate_ephemeral_key();
    
    // 3. Firma (Nc || Ns || Epub_S) con privKc caricata all'avvio
    
    // 4. Invia ServerHello (Ns, Epub_S, Firma) al client
    
    // 5. Riceve ClientKeyExchange (Epub_C)
    
    // 6. Calcola derive_shared_secret(...) ed esegue HKDF
    
    // 7. Entra nel loop di servizio in attesa dei comandi (Auth, Timestamp, Balance)
    // decifrando i payload con AES-GCM.
}

int main() {
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