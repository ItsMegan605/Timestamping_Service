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

#define DEFAULT_PORT 8080;
#define HASH_LEN 32;
#define MAX_MESSAGE_SIZE 65536;

using namespace std;


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

int main(int argc, char* argv[]) {
    // TODO: Implement everything described above
    return 0;
}