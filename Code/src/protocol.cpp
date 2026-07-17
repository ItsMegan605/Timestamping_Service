#include "../header_files/protocol.h"
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h> 

using namespace std;

// Sends a message over the socket, prepending a 4-byte length header in network byte order
bool send_message(int socket_fd, const vector<uint8_t>& payload) {
    uint32_t payload_len = static_cast<uint32_t>(payload.size());
    if (payload_len > MAX_MESSAGE_SIZE) return false;   

    uint32_t net_len = htonl(payload_len);
    vector<uint8_t> send_buffer;
    send_buffer.reserve(4 + payload_len);

    const uint8_t* len_bytes = reinterpret_cast<const uint8_t*>(&net_len);
    send_buffer.insert(send_buffer.end(), len_bytes, len_bytes + 4);
    send_buffer.insert(send_buffer.end(), payload.begin(), payload.end());

    size_t total_sent = 0;
    const size_t total_to_send = send_buffer.size();

    // Loop until all bytes are transmitted
    while (total_sent < total_to_send) {
        ssize_t bytes_sent = send(socket_fd, send_buffer.data() + total_sent, total_to_send - total_sent, 0);
        if (bytes_sent <= 0) return false;
        total_sent += static_cast<size_t>(bytes_sent);
    }
    return true;
}

// Receives a message, reading the 4-byte header first to determine the payload size
bool recv_message(int socket_fd, vector<uint8_t>& out_payload) {
    uint8_t len_buf[4];
    size_t total_received = 0;

    while (total_received < 4) {
        ssize_t bytes_recv = recv(socket_fd, len_buf + total_received, 4 - total_received, 0);
        if (bytes_recv <= 0) return false;
        total_received += static_cast<size_t>(bytes_recv);
    }

    uint32_t net_len;
    memcpy(&net_len, len_buf, 4);
    uint32_t payload_len = ntohl(net_len);

    if (payload_len == 0) {
        out_payload.clear();
        return true;
    }
    if (payload_len > MAX_MESSAGE_SIZE) return false;

    out_payload.resize(payload_len);
    total_received = 0;

    // Read exactly payload_len bytes from the socket
    while (total_received < payload_len) {
        ssize_t bytes_recv = recv(socket_fd, out_payload.data() + total_received, payload_len - total_received, 0);
        if (bytes_recv <= 0) return false;
        total_received += static_cast<size_t>(bytes_recv);
    }
    return true;
}

// Packs the Client Hello parameters: [2 bytes key len] + [Epub_C] + [Nonce]
vector<uint8_t> pack_client_hello(const vector<uint8_t>& epub_c, const vector<uint8_t>& nc) {
    vector<uint8_t> buffer;
    uint16_t key_len = htons(static_cast<uint16_t>(epub_c.size()));
    const uint8_t* len_ptr = reinterpret_cast<const uint8_t*>(&key_len);
    
    buffer.insert(buffer.end(), len_ptr, len_ptr + 2);
    buffer.insert(buffer.end(), epub_c.begin(), epub_c.end());
    buffer.insert(buffer.end(), nc.begin(), nc.end());
    
    return buffer;
}

bool unpack_client_hello(const vector<uint8_t>& payload, vector<uint8_t>& out_epub_c, vector<uint8_t>& out_nc) {
    if (payload.size() < 2) return false;
    
    uint16_t key_len_net;
    memcpy(&key_len_net, payload.data(), 2);
    uint16_t key_len = ntohs(key_len_net);

    // Validate overall length
    if (payload.size() != 2 + key_len + NONCE_SIZE) return false;

    out_epub_c.assign(payload.begin() + 2, payload.begin() + 2 + key_len);
    out_nc.assign(payload.begin() + 2 + key_len, payload.end());
    
    return true;
}

// Packs the Server Hello parameters: [2 bytes key len] + [Epub_S] + [Nonce] + [2 bytes sig len] + [Signature]
vector<uint8_t> pack_server_hello(const vector<uint8_t>& epub_s, const vector<uint8_t>& ns, const vector<uint8_t>& signature) {
    vector<uint8_t> buffer;
    uint16_t key_len = htons(static_cast<uint16_t>(epub_s.size()));
    uint16_t sig_len = htons(static_cast<uint16_t>(signature.size()));

    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&key_len), reinterpret_cast<uint8_t*>(&key_len) + 2);
    buffer.insert(buffer.end(), epub_s.begin(), epub_s.end());
    
    buffer.insert(buffer.end(), ns.begin(), ns.end());
    
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&sig_len), reinterpret_cast<uint8_t*>(&sig_len) + 2);
    buffer.insert(buffer.end(), signature.begin(), signature.end());
    
    return buffer;
}

bool unpack_server_hello(const vector<uint8_t>& payload, vector<uint8_t>& out_epub_s, vector<uint8_t>& out_ns, vector<uint8_t>& out_signature) {
    if (payload.size() < 2) return false;
    size_t offset = 0;

    // Extract Epub_S
    uint16_t key_len;
    memcpy(&key_len, payload.data() + offset, 2);
    key_len = ntohs(key_len);
    offset += 2;

    if (payload.size() < offset + key_len + NONCE_SIZE + 2) return false; 

    out_epub_s.assign(payload.begin() + offset, payload.begin() + offset + key_len);
    offset += key_len;

    // Extract Ns
    out_ns.assign(payload.begin() + offset, payload.begin() + offset + NONCE_SIZE);
    offset += NONCE_SIZE;

    // Extract Signature
    uint16_t sig_len;
    memcpy(&sig_len, payload.data() + offset, 2);
    sig_len = ntohs(sig_len);
    offset += 2;

    if (payload.size() != offset + sig_len) return false;

    out_signature.assign(payload.begin() + offset, payload.begin() + offset + sig_len);
    return true;
}

// Packs the AuthRequest struct into a byte vector: [2 bytes username len] + [username] + [2 bytes password len] + [password]
vector<uint8_t> pack_auth_request(const AuthRequest& req) {
    vector<uint8_t> out;

    // Validate lengths before packing
    uint16_t username_len = static_cast<uint16_t>(req.username.size());
    uint16_t password_len = static_cast<uint16_t>(req.password.size());

    // Convert to network byte order
    uint16_t username_len_net = htons(username_len);
    uint16_t password_len_net = htons(password_len);
    
    // Pack username length and username
    out.insert(out.end(), reinterpret_cast<uint8_t*>(&username_len_net), reinterpret_cast<uint8_t*>(&username_len_net) + 2);
    out.insert(out.end(), req.username.begin(), req.username.end());

    // Pack password length and password
    out.insert(out.end(), reinterpret_cast<uint8_t*>(&password_len_net), reinterpret_cast<uint8_t*>(&password_len_net) + 2);
    out.insert(out.end(), req.password.begin(), req.password.end());
    return out;
}

bool unpack_auth_request(const vector<uint8_t>& payload, AuthRequest& out) {
    if (payload.size() < 4) return false; // Minimum size check: 2 bytes for username length and 2 bytes for password length = 4 bytes
    
    // constants for validation
    const uint16_t MAX_USERNAME_LEN = 64; 
    const uint16_t MAX_PASSWORD_LEN = 128; 

    size_t offset = 0;

    // read username length
    uint16_t username_len_net;
    memcpy(&username_len_net, payload.data() + offset, 2);
    offset += 2;
    uint16_t username_len = ntohs(username_len_net);

    // Validate username length
    if (username_len == 0 || username_len > MAX_USERNAME_LEN) return false;

    // Check if there's enough bytes for username and password length
    if (payload.size() < offset + username_len + 2) return false; 

    // extract username
    out.username.assign(payload.begin() + offset, payload.begin() + offset + username_len);
    offset += username_len;

    // read password length
    uint16_t password_len_net;
    memcpy(&password_len_net, payload.data() + offset, 2);
    offset += 2;
    uint16_t password_len = ntohs(password_len_net);

    // Validate password length
    if (password_len == 0 || password_len > MAX_PASSWORD_LEN) return false;

    // Check if there's enough bytes for password
    if (payload.size() < offset + password_len) return false;

    // extract password
    out.password.assign(payload.begin() + offset, payload.begin() + offset + password_len);
    return true;
}

// Packs the AuthResponse struct into a byte vector: [1 byte status]
vector<uint8_t> pack_auth_response(const AuthResponse& res) {
    return vector<uint8_t>{static_cast<uint8_t>(res.status)};
}

bool unpack_auth_response(const vector<uint8_t>& payload, AuthResponse& out) {
    if (payload.size() != 1) return false; // AuthResponse should be exactly 1 byte
    
    uint8_t status_byte = payload[0];
    // validate that the status byte corresponds to a valid Status enum value
    if (status_byte > static_cast<uint8_t>(Status::INTERNAL_ERROR)) return false;
    
    out.status = static_cast<Status>(payload[0]);
    return true;
}

