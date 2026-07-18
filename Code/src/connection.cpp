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

using namespace std; // Acceptable in .cpp files, but strictly avoid in .h files.

// ==============================================================================
// CLIENT SIDE
// ==============================================================================

/**
 * server_connection
 * 
 * Establishes a blocking TCP connection to the specified server IP and port.
 * Returns the connected socket file descriptor on success, or -1 on failure.
 */
int server_connection(const char *ip, int port) {
    // Create an IPv4 (AF_INET) and TCP (SOCK_STREAM) socket.
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        cerr << "Error creating socket" << endl;
        return -1;
    }

    // Initialize the server address structure.
    // Using {} ensures all fields (including padding) are zeroed out safely.
    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    
    // Convert the port number to Network Byte Order (Big-Endian).
    server_address.sin_port = htons(port); 

    // Convert the IP address from a human-readable text string to binary format.
    if (inet_pton(AF_INET, ip, &server_address.sin_addr) <= 0) {
        cerr << "Invalid IP address" << endl;
        close(client_socket); // Clean up the socket before returning
        return -1;
    }

    // Initiate the TCP 3-way handshake (SYN, SYN-ACK, ACK).
    // This is a blocking call; the thread will wait until connected or timed out.
    if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        cerr << "Connection failed" << endl;
        close(client_socket); // Clean up the socket before returning
        return -1;
    }
    
    return client_socket;
}

// ==============================================================================
// SERVER SIDE
// ==============================================================================

/**
 * setup_server
 * 
 * Sets up a passive listening TCP socket on the specified port.
 * Returns the listening socket file descriptor on success, or -1 on failure.
 */
int setup_server(int port) {
    // Create an IPv4 (AF_INET) and TCP (SOCK_STREAM) socket.
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        cerr << "Error creating server socket" << endl;
        return -1;
    }

    // Configure the socket to allow immediate port reuse.
    // This bypasses the TCP TIME_WAIT state, preventing "Address already in use" 
    // errors if the server is killed and restarted immediately.
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "Warning: setsockopt SO_REUSEADDR failed" << endl;
    }

    // Configure the server address structure.
    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    
    // INADDR_ANY allows the server to bind to all available network interfaces.
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(port);

    // Bind the socket to the specified IP address and port.
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        cerr << "Bind error" << endl;
        close(server_fd); // Clean up
        return -1;
    }

    // Transition the socket into a passive listening state.
    // The backlog is set to 5, meaning the OS will queue up to 5 pending connections
    // before refusing new ones. (Consider using SOMAXCONN for production).
    if (listen(server_fd, 5) < 0) {
        cerr << "Listen error" << endl;
        close(server_fd); // Clean up
        return -1;
    }

    // Return the passive socket descriptor, ready to be passed to accept().
    return server_fd;
}

// ==============================================================================
// TODO BLOCKS: MODERN C++ RAII ENCAPSULATION
// ==============================================================================

// TODO: [RAII SOCKET MANAGEMENT]
// Currently, the socket descriptors are returned as raw raw integers (`int`). 
// If an exception is thrown or a function returns early somewhere else in the code, 
// the `close(socket_fd)` call might be missed, causing a resource leak.
// 
// To make this 100% modern C++, consider creating a `SocketWrapper` class 
// or using a `std::unique_ptr` with a custom deleter to manage the file descriptor.
// 
// Example:
// class SocketWrapper {
//     int fd;
// public:
//     explicit SocketWrapper(int descriptor) : fd(descriptor) {}
//     ~SocketWrapper() { if (fd >= 0) close(fd); }
//     int get() const { return fd; }
//     void release() { fd = -1; }
//     // Delete copy constructor and copy assignment to enforce unique ownership
//     SocketWrapper(const SocketWrapper&) = delete;
//     SocketWrapper& operator=(const SocketWrapper&) = delete;
// };