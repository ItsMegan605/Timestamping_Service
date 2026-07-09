#include "../header_files/common.h"
#include "../header_files/crypto.h"
#include "../header_files/protocol.h"

int main() {
    // 1. Connessione TCP
    int sock = server_connection(IP_ADDRESS, DEFAULT_PORT);
    
    // 2. Genera il Nonce e invia ClientHello
    std::vector<uint8_t> nc = generate_nonce(32); // Da implementare in crypto.cpp
    // Invia nc sul socket...
    
    // 3. Riceve ServerHello (Ns, Epub_S, Firma)
    // Legge dal socket...
    
    // 4. Verifica Firma del Server
    // Se verify_signature(...) fallisce -> disconnetti e abortisci
    
    // 5. Genera la propria chiave ECDHE e deriva il segreto
    EVP_PKEY* client_eph_key = generate_ephemeral_key();
    // Invia Epub_C al server...
    // calcola derive_shared_secret(...)
    
    // 6. Passa il segreto a HKDF per generare le chiavi AES
    
    // 7. Il canale sicuro è pronto. Procedi con AuthRequest cifrata in AES-GCM.
}