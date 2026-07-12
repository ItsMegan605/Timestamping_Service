/**
 * test_client.cpp - A minimal test harness to verify send_message / recv_message.
 * 
 * This client connects to the test server, sends test messages,
 * and prints the echoed replies. No crypto – just raw framing over TCP.
 * 
 * Note: Empty messages are tested separately, as they have special handling.
 */

#include "../header_files/common.h"
#include "../header_files/protocol.h"
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <signal.h>
#include <cstdlib>

using namespace std;

int main() {
    // Ignore SIGPIPE so the client doesn't crash if the server disconnects
    signal(SIGPIPE, SIG_IGN);

    cout << "[Test Client] Connecting to " << IP_ADDRESS << ":" << DEFAULT_PORT << " ..." << endl;

    int sock = server_connection(IP_ADDRESS, DEFAULT_PORT);
    if (sock < 0) {
        cerr << "[Test Client] Connection failed" << endl;
        return EXIT_FAILURE;
    }

    cout << "[Test Client] Connected successfully!" << endl;

    // Prepare test messages (no empty message to avoid blocking)
    vector<string> test_messages = {
        "Hello, Server!",
        "This is message #2",
        "The quick brown fox jumps over the lazy dog",
        "12345"
    };

    // Send each message and wait for the echo
    for (size_t i = 0; i < test_messages.size(); i++) {
        const string& msg = test_messages[i];
        vector<uint8_t> payload(msg.begin(), msg.end());

        cout << "[Test Client] Sending message " << i + 1 << ": \"" << msg << "\""
             << " (size: " << payload.size() << " bytes)" << endl;

        if (!send_message(sock, payload)) {
            cerr << "[Test Client] send_message failed!" << endl;
            break;
        }

        // Wait for the echoed reply
        vector<uint8_t> reply;
        if (!recv_message(sock, reply)) {
            cerr << "[Test Client] recv_message failed! Server may have disconnected." << endl;
            break;
        }

        string reply_str(reply.begin(), reply.end());
        cout << "[Test Client] Received echo #" << i + 1 << ": \"" << reply_str << "\""
             << " (size: " << reply.size() << " bytes)" << endl;
        cout << endl;
    }

    cout << "[Test Client] Test complete. Closing connection." << endl;
    close(sock);
    return EXIT_SUCCESS;
}