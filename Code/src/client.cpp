#include "../header_files/common.h"
#include "../header_files/crypto.h"
#include "../header_files/protocol.h"
#include <iostream>
#include <unistd.h>
#include <cstdlib>

int main() {
    // 1. Connessione TCP
    int sock = server_connection(IP_ADDRESS, DEFAULT_PORT);
    if (sock <0) return EXIT_FAILURE;
    
    // 2. Genera il Nonce e invia ClientHello
    std::vector<uint8_t> nc = generate_nonce(32); // Da implementare in crypto.cpp
    // Invia nc sul socket...
    
    // 3. Riceve ServerHello (Ns, Epub_S, Firma)
    // Legge dal socket and parse into structs
    
    // 4. Verifica Firma del Server using pucKx (caricata da PEM)
    // Se verify_signature(...) fallisce -> disconnetti e abortisci
    
    // 5. Genera la propria chiave ECDHE(Epub_C) e deriva il segreto
    EVP_PKEY* client_eph_key = generate_ephemeral_key();
    // Invia Epub_C (serialized) al server...
    // calcola derive_shared_secret(...)
    
    // 6. Passa il segreto a HKDF per generare le chiavi AES (enk_key + iv)
    
    // 7. Il canale sicuro è pronto. Procedi con AuthRequest cifrata in AES-GCM.
    // TODO: pack AuthRequest, encrypt with aes_gcm_encrypt (include seq num in AAD)
    // TODO: send encrypted message via send_message() from protocol.h
    // TODO: wait for AuthResponse, decrypt and verify
    
    // 8. Se autenticato, esegui il comando richiesto (timestamp o balance)
    //    oppure fai il loop interattivo.
    
    close(sock);
    return 0;
}