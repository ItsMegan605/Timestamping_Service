/**
 * protocol.cpp - Implements all serialization/deserialization logic.
 * 
 * This module operates on raw TCP sockets (int socket_fd).
 * It does NOT use OpenSSL TLS/SSL functions.
 * Encryption/decryption is handled by using AES-GCM.
 * 
 * TODO: For pack functions:
 *   - The first byte of the payload must be the Command (from common.h).
 *   - Use htons(), htonl(), htobe64() for all integers.
 *   - Prepend length prefixes (e.g., uint16_t for strings) where needed.
 *   - Return a flat vector<uint8_t>.
 * 
 * TODO: For unpack functions:
 *   - Verify minimum length (atleast 1 byte for status).
 *   - Read integers with ntohs(), ntohl(), be64toh().
 *   - Return false if malformed or if the status is unknown.
 * 
 * TODO: For send_message:
 *   - Prepend the message length as a 4-byte big-endian integer.
 *   - Call send() in a loop until all bytes (length prefix + payload) are transmitted.
 * 
 * TODO: For recv_message:
 *   - Read the first 4 bytes to get the payload length (use recv() in a loop).
 *   - Loop recv() until the exact number of bytes is received.
 *   - Return the payload in out_data.
 */

#include "../header_files/protocol.h"
#include <cstring>
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>  // for htonl / ntohl
#include <unistd.h>      // for close
#include <cerrno>

// send message - takes payload, prepends length, and sends both over socket_fd, loops until all bytes are sent
bool send_message(int socket_fd, const std::vector<uint8_t>& payload) {
    //Check payload size
    uint32_t payload_len = static_cast<uint32_t>(payload.size());
    if (payload_len > MAX_MESSAGE_SIZE) {
        return false;   // payload is too large
    }

    //Convert length to network byte order (big-endian)
    uint32_t net_len = htonl(payload_len);

    //Build the send buffer: [4-byte length] + [payload]
    std::vector<uint8_t> send_buffer;
    send_buffer.reserve(4 + payload_len);

    //Copy the 4 bytes of the length header
    const uint8_t* len_bytes = reinterpret_cast<const uint8_t*>(&net_len);
    send_buffer.insert(send_buffer.end(), len_bytes, len_bytes + 4);

    //Copy the payload
    send_buffer.insert(send_buffer.end(), payload.begin(), payload.end());

    //Send everything in a loop (handle partial sends)
    size_t total_sent = 0;
    const size_t total_to_send = send_buffer.size();

    while (total_sent < total_to_send) {
        ssize_t bytes_sent = send(socket_fd,
                                send_buffer.data() + total_sent,
                                total_to_send - total_sent,
                                0);   // flags = 0 (blocking)

        if (bytes_sent == -1) {
            // Error occurred (e.g., broken pipe)
            return false;
        }

        if (bytes_sent == 0) {
            // Connection was closed by the peer
            return false;
        }

        total_sent += static_cast<size_t>(bytes_sent);
    }

    return true;
}


// recv message - reads 4-byte length prefix, then reads the exact number of bytes specified by the length, loops until the full payload is received, returns payload in out_payload
bool recv_message(int socket_fd, std::vector<uint8_t>& out_payload) {
    //Read exactly 4 bytes for the length prefix
    uint8_t len_buf[4];
    size_t total_received = 0;

    while (total_received < 4) {
        ssize_t bytes_recv = recv(socket_fd,
                                len_buf + total_received,
                                4 - total_received,
                                0);   // flags = 0 (blocking)

        if (bytes_recv == -1) {
            return false;   // socket error
        }

        if (bytes_recv == 0) {
            return false;   // peer closed the connection
        }

        total_received += static_cast<size_t>(bytes_recv);
    }

    //Decode the length (convert from network to host byte order)
    uint32_t net_len;
    std::memcpy(&net_len, len_buf, 4);
    uint32_t payload_len = ntohl(net_len);

    //Validate the length (security check)
    if (payload_len == 0) {
        // Empty payload is allowed
        out_payload.clear();
        return true;
    }

    // check for maliciously large payloads to prevent exhaustion attacks
    if (payload_len > MAX_MESSAGE_SIZE) {
        // Malicious or corrupted message - reject it
        return false;
    }

    //Read exactly 'payload_len' bytes
    out_payload.resize(payload_len);
    total_received = 0;

    while (total_received < payload_len) {
        ssize_t bytes_recv = recv(socket_fd,
                                  out_payload.data() + total_received,
                                  payload_len - total_received,
                                  0);

        if (bytes_recv == -1) {
            return false;   // socket error
        }

        if (bytes_recv == 0) {
            return false;   // peer disconnected mid-message
        }

        total_received += static_cast<size_t>(bytes_recv);
    }

    return true;
}
