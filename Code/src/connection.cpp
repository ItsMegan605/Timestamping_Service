/*
 * Client-Server TCP connection module
 */

#include "../header_files/common.h"
#include "../header_files/crypto.h"
#include <cstdint>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

// Function used by the Client to connect to the Server
int server_connection(const char *ip, int port) {
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        cerr << "Error creating socket" << endl;
        return -1;
    }

    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &server_address.sin_addr) <= 0) {
        cerr << "Invalid IP address" << endl;
        return -1;
    }

    if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        cerr << "Connection failed" << endl;
        return -1;
    }
    return client_socket;
}

// Function used by the Server to start listening
int setup_server(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        cerr << "Error creating server socket" << endl;
        return -1;
    }

    // Avoid "Address already in use" error if the server is restarted quickly
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "Warning: setsockopt SO_REUSEADDR failed" << endl;
    }

    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        cerr << "Bind error" << endl;
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 5) < 0) {
        cerr << "Listen error" << endl;
        close(server_fd);
        return -1;
    }

    return server_fd;
}