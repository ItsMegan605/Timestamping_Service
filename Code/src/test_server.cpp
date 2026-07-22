/**
 * test_server.cpp - A minimal test harness to verify send_message / recv_message.
 * 
 * This server listens on DEFAULT_PORT, accepts a single client connection,
 * receives messages, prints them, and echoes them back.
 * No crypto – just raw framing over TCP.
 */

#include "../header_files/common.h"
#include "../header_files/protocol.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>   // for signal() and SIGPIPE

using namespace std;

int main() {
    // Ignore SIGPIPE so the server doesn't crash if the client disconnects abruptly
    signal(SIGPIPE, SIG_IGN);

    // Setup the server socket
    int server_fd = setup_server(DEFAULT_PORT);
    if (server_fd < 0) {
        cerr << "Failed to set up server on port " << DEFAULT_PORT << endl;
        return EXIT_FAILURE;
    }

    cout << "[Test Server] Listening on port " << DEFAULT_PORT << endl;
    cout << "[Test Server] Waiting for a single client connection..." << endl;

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) {
        cerr << "[Test Server] Accept failed" << endl;
        close(server_fd);
        return EXIT_FAILURE;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    cout << "[Test Server] Client connected from " << client_ip << ":" 
        << ntohs(client_addr.sin_port) << endl;

    // --- Main test loop: receive messages and echo them back ---
    // Keep running until the client disconnects(recv_message returns false) 
    int message_count = 0;
    while (true) {
        vector<uint8_t> received_payload;

        cout << "[Test Server] Waiting for message " << message_count + 1 << " ..." << endl;
        bool ok = recv_message(client_fd, received_payload);

        if (!ok) {
            cout << "[Test Server] Client disconnected. Exiting." << endl;
            break;
        }

        message_count++;

        if (received_payload.empty()) {
            cout << "[Test Server] Received empty message (length 0)." << endl;
        } else {
            // Convert payload to string for printing (assuming it's ASCII text)
            string message(received_payload.begin(), received_payload.end());
            cout << "[Test Server] Received (#" << message_count << "): \"" << message << "\"" 
                << " (size: " << received_payload.size() << " bytes)" << endl;

            // Echo the same message back to the client
            cout << "[Test Server] Echoing back..." << endl;
            if (!send_message(client_fd, received_payload)) {
                cerr << "[Test Server] send_message failed!" << endl;
                break;
            }
        }
    }

    cout << "[Test Server] Test complete. Closing connection." << endl;
    close(client_fd);
    close(server_fd);
    return EXIT_SUCCESS;
}