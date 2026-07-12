/*
Client-Server connection code 
*/

#include "../header_files/common.h"
#include "../header_files/crypto.h"
#include <cstdint>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

// Funzione usata dal Client per connettersi al Server
int server_connection(const char *ip, int port) {
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        std::cerr << "Errore creazione socket" << std::endl;
        return -1;
    }

    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &server_address.sin_addr) <= 0) {
        std::cerr << "Indirizzo IP non valido" << std::endl;
        return -1;
    }

    if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Connessione fallita" << std::endl;
        return -1;
    }
    return client_socket;
}

// Funzione usata dal Server per mettersi in ascolto
int setup_server(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "Errore nella creazione del socket server" << std::endl;
        return -1;
    }

    // Evita l'errore "Address already in use" se riavvii il server velocemente
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Attenzione: setsockopt SO_REUSEADDR fallita" << std::endl;
    }

    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Errore nel bind" << std::endl;
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 5) < 0) {
        std::cerr << "Errore nella listen" << std::endl;
        close(server_fd);
        return -1;
    }

    return server_fd;
}