#include "../header_files/protocol.h"
#include "../header_files/crypto.h"
#include "../header_files/interface.h"
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h> 
#include <openssl/rand.h>

using namespace std;

// ==============================================================================
// RAW TCP FRAMING FUNCTIONS
// ==============================================================================

/**
 * send_message
 * 
 * Sends a raw message over the socket using a Length-Value framing approach.
 * It calculates the payload size, converts it to Network Byte Order (Big-Endian)
 * to ensure cross-architecture compatibility, prepends this 4-byte header to the
 * payload, and pushes everything through the TCP socket.
 */
bool send_message(int socket_fd, const vector<uint8_t>& payload) {
    uint32_t payload_len = static_cast<uint32_t>(payload.size());
    if (payload_len > MAX_MESSAGE_SIZE) return false;   

    uint32_t net_len = htonl(payload_len);
    vector<uint8_t> send_buffer;
    send_buffer.reserve(4 + payload_len);

    // Safely copy the 4-byte length into the buffer
    uint8_t len_bytes[4];
    memcpy(len_bytes, &net_len, 4);
    send_buffer.insert(send_buffer.end(), len_bytes, len_bytes + 4);
    
    // Append the actual payload
    send_buffer.insert(send_buffer.end(), payload.begin(), payload.end());

    size_t total_sent = 0;
    const size_t total_to_send = send_buffer.size();

    // Loop until all bytes are transmitted (handles TCP fragmentation)
    while (total_sent < total_to_send) {
        ssize_t bytes_sent = send(socket_fd, send_buffer.data() + total_sent, total_to_send - total_sent, 0);
        if (bytes_sent <= 0) return false;
        total_sent += static_cast<size_t>(bytes_sent);
    }
    return true;
}

/**
 * recv_message
 * 
 * Receives a message by first reading exactly 4 bytes to determine the payload 
 * length, converts it back to Host Byte Order, allocates the necessary memory, 
 * and then reads the exact amount of payload bytes. 
 * Includes protection against Out-Of-Memory (OOM) attacks.
 */
bool recv_message(int socket_fd, vector<uint8_t>& out_payload) {
    uint8_t len_buf[4];
    size_t total_received = 0;

    // 1. Read the 4-byte length header
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
    
    // Security check: drop excessively large messages
    if (payload_len > MAX_MESSAGE_SIZE) return false;

    out_payload.resize(payload_len);
    total_received = 0;

    // 2. Read exactly payload_len bytes from the socket
    while (total_received < payload_len) {
        ssize_t bytes_recv = recv(socket_fd, out_payload.data() + total_received, payload_len - total_received, 0);
        if (bytes_recv <= 0) return false;
        total_received += static_cast<size_t>(bytes_recv);
    }
    return true;
}

// TODO: (Secure Channel) Implement AES-GCM secure messaging functions here.
// You need:
// bool send_secure_message(int socket_fd, const vector<uint8_t>& cleartext, const vector<uint8_t>& aes_key, vector<uint8_t>& iv, uint64_t& seq_num);
// bool recv_secure_message(int socket_fd, vector<uint8_t>& out_cleartext, const vector<uint8_t>& aes_key, vector<uint8_t>& iv, uint64_t& expected_seq_num);
// These functions will use EVP_Encrypt* / EVP_Decrypt* with AES-256-GCM, increment the seq_num to prevent Replay Attacks, 
// append the GCM TAG for integrity/non-malleability, and call the raw send_message/recv_message under the hood.


// ==============================================================================
// HANDSHAKE SERIALIZATION (UNENCRYPTED)
// ==============================================================================

/**
 * pack_client_hello
 * 
 * Serializes the Client Hello parameters.
 * Format: [2 bytes key len] + [Epub_C] + [Nonce_C]
 */
vector<uint8_t> pack_client_hello(const vector<uint8_t>& epub_c, const vector<uint8_t>& nc) {
    vector<uint8_t> buffer;
    uint16_t key_len = htons(static_cast<uint16_t>(epub_c.size()));
    
    uint8_t len_bytes[2];
    memcpy(len_bytes, &key_len, 2);
    
    buffer.insert(buffer.end(), len_bytes, len_bytes + 2);
    buffer.insert(buffer.end(), epub_c.begin(), epub_c.end());
    buffer.insert(buffer.end(), nc.begin(), nc.end());
    
    return buffer;
}

/**
 * unpack_client_hello
 * 
 * Deserializes the Client Hello parameters, verifying strict boundaries.
 */
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

/**
 * pack_server_hello
 * 
 * Serializes the Server Hello parameters.
 * Current Format: [2 bytes key len] + [Epub_S] + [Nonce_S] + [2 bytes sig len] + [Signature]
 */
vector<uint8_t> pack_server_hello(const vector<uint8_t>& epub_s, const vector<uint8_t>& ns, const vector<uint8_t>& signature) {
    // Modify this function to accept `const vector<uint8_t>& cert_der` as a parameter.
    // The new format should be: [2B cert len] + [Certificate] + [2B key len] + [Epub_S] + [Nonce_S] + [2B sig len] + [Signature]
    
    vector<uint8_t> buffer;
    uint16_t key_len = htons(static_cast<uint16_t>(epub_s.size()));
    uint16_t sig_len = htons(static_cast<uint16_t>(signature.size()));

    uint8_t len_bytes[2];
    
    // Pack Epub_S
    memcpy(len_bytes, &key_len, 2);
    buffer.insert(buffer.end(), len_bytes, len_bytes + 2);
    buffer.insert(buffer.end(), epub_s.begin(), epub_s.end());
    
    // Pack Server Nonce (Ns)
    buffer.insert(buffer.end(), ns.begin(), ns.end());
    
    // Pack Signature
    memcpy(len_bytes, &sig_len, 2);
    buffer.insert(buffer.end(), len_bytes, len_bytes + 2);
    buffer.insert(buffer.end(), signature.begin(), signature.end());
    
    return buffer;
}

/**
 * unpack_server_hello
 * 
 * Deserializes the Server Hello parameters sequentially using an offset tracker.
 */
bool unpack_server_hello(const vector<uint8_t>& payload, vector<uint8_t>& out_epub_s, vector<uint8_t>& out_ns, vector<uint8_t>& out_signature) {
    // corresponding to the changes in pack_server_hello. Add `vector<uint8_t>& out_cert` to parameters.
    
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


// ==============================================================================
// APPLICATION LAYER SERIALIZATION (ENCRYPTED VIA SECURE CHANNEL)
// ==============================================================================

/**
 * pack_auth_request
 * 
 * Serializes the authentication credentials.
 * Format: [2 bytes username len] + [username] + [2 bytes password len] + [password]
 */
vector<uint8_t> pack_auth_request(const AuthRequest& req) {
    vector<uint8_t> out;

    uint16_t username_len = static_cast<uint16_t>(req.username.size());
    uint16_t password_len = static_cast<uint16_t>(req.password.size());

    uint16_t username_len_net = htons(username_len);
    uint16_t password_len_net = htons(password_len);
    
    uint8_t len_bytes[2];
    
    // Pack username
    memcpy(len_bytes, &username_len_net, 2);
    out.insert(out.end(), len_bytes, len_bytes + 2);
    out.insert(out.end(), req.username.begin(), req.username.end());

    // Pack password
    memcpy(len_bytes, &password_len_net, 2);
    out.insert(out.end(), len_bytes, len_bytes + 2);
    out.insert(out.end(), req.password.begin(), req.password.end());
    
    return out;
}

/**
 * unpack_auth_request
 * 
 * Deserializes the authentication credentials, protecting against invalid lengths.
 */
bool unpack_auth_request(const vector<uint8_t>& payload, AuthRequest& out) {
    if (payload.size() < 4) return false; 
    
    const uint16_t MAX_USERNAME_LEN = 64; 
    const uint16_t MAX_PASSWORD_LEN = 128; 

    size_t offset = 0;

    // read username length
    uint16_t username_len_net;
    memcpy(&username_len_net, payload.data() + offset, 2);
    offset += 2;
    uint16_t username_len = ntohs(username_len_net);

    if (username_len == 0 || username_len > MAX_USERNAME_LEN) return false;
    if (payload.size() < offset + username_len + 2) return false; 

    // extract username
    out.username.assign(payload.begin() + offset, payload.begin() + offset + username_len);
    offset += username_len;

    // read password length
    uint16_t password_len_net;
    memcpy(&password_len_net, payload.data() + offset, 2);
    offset += 2;
    uint16_t password_len = ntohs(password_len_net);

    if (password_len == 0 || password_len > MAX_PASSWORD_LEN) return false;
    if (payload.size() < offset + password_len) return false;

    // extract password
    out.password.assign(payload.begin() + offset, payload.begin() + offset + password_len);
    return true;
}

/**
 * pack_auth_response
 * 
 * Serializes the authentication response. It is a single byte representing the Status enum.
 */
vector<uint8_t> pack_auth_response(const AuthResponse& res) {
    return vector<uint8_t>{static_cast<uint8_t>(res.status)};
}

/**
 * unpack_auth_response
 * 
 * Deserializes the authentication response, validating the Status enum range.
 */
bool unpack_auth_response(const vector<uint8_t>& payload, AuthResponse& out) {
    if (payload.size() != 1) return false; 
    
    uint8_t status_byte = payload[0];
    if (status_byte > static_cast<uint8_t>(Status::INTERNAL_ERROR)) return false;
    
    out.status = static_cast<Status>(payload[0]);
    return true;
}

//functions to enchypt data so that they are not in the clear
bool send_secure_message(int socket_fd, const vector<uint8_t>& cleartext, const vector<uint8_t>& aes_key, vector<uint8_t>& iv, uint64_t& seq_num){
    // Generate a fresh random IV for this specific message (12 bytes is standard for GCM)
    vector<uint8_t> local_iv(12);
    if (RAND_bytes(local_iv.data(), 12) != 1) return false;

    vector<uint8_t> ciphertext(cleartext.size() + 16); 
    vector<uint8_t> tag(16);

    // Encrypt and authenticate, using seq_num as AAD
    int ciphertext_len = encrypt_aes_gcm_256(
        cleartext.data(), cleartext.size(),
        reinterpret_cast<const unsigned char*>(&seq_num), sizeof(seq_num),
        aes_key.data(), local_iv.data(),
        ciphertext.data(), tag.data()
    );

    if (ciphertext_len < 0) return false;
    ciphertext.resize(ciphertext_len);

    // Assemble the final payload: [12 bytes IV] + [Ciphertext] + [16 bytes TAG]
    vector<uint8_t> payload_to_send;
    payload_to_send.insert(payload_to_send.end(), local_iv.begin(), local_iv.end());
    payload_to_send.insert(payload_to_send.end(), ciphertext.begin(), ciphertext.end());
    payload_to_send.insert(payload_to_send.end(), tag.begin(), tag.end());

    // Increment sequence number for the next transmission
    seq_num++;

    // Send over the wire using your existing TCP framing function
    return send_message(socket_fd, payload_to_send);
}


bool recv_secure_message(int socket_fd, vector<uint8_t>& out_cleartext, const vector<uint8_t>& aes_key, vector<uint8_t>& iv, uint64_t& expected_seq_num) {
    vector<uint8_t> raw_payload;
    
    // Receive the raw bytes from the network
    if (!recv_message(socket_fd, raw_payload)) return false;

    // Minimum size check: must contain at least a 12-byte IV and a 16-byte TAG
    if (raw_payload.size() < 28) return false; 

    // Extract the components
    vector<uint8_t> received_iv(raw_payload.begin(), raw_payload.begin() + 12);
    vector<uint8_t> received_tag(raw_payload.end() - 16, raw_payload.end());
    vector<uint8_t> ciphertext(raw_payload.begin() + 12, raw_payload.end() - 16);

    out_cleartext.resize(ciphertext.size());

    // Decrypt and verify authenticity using the expected seq_num as AAD
    int plaintext_len = decrypt_aes_gcm_256(
        ciphertext.data(), ciphertext.size(),
        reinterpret_cast<const unsigned char*>(&expected_seq_num), sizeof(expected_seq_num),
        aes_key.data(), received_iv.data(),
        out_cleartext.data(), received_tag.data()
    );

    // If decrypt returns < 0, the message was tampered with, the key is wrong, or it's a replay attack
    if (plaintext_len < 0) {
        out_cleartext.clear();
        return false;
    }

    out_cleartext.resize(plaintext_len);
    
    // Increment the sequence number for the next reception
    expected_seq_num++;

    return true;
}


// user requested functions 
vector<uint8_t> getUserBalance() {
    printBanner("Balance request submitted. Here is your balance:", BOLD_MAGENTA);
    //todo
}

vector<uint8_t> getUserTimestamp() {
    printBanner("Timestamp request submitted.", BOLD_CYAN);
    //todo
}

vector<uint8_t> userVerification() {
    printBanner("Let's verify your timestamp.", BOLD_GREEN);
    //todo
}

// TODO: (Service Layer) Implement packing/unpacking for Timestamp and Balance operations.
// 
// vector<uint8_t> pack_timestamp_request(const TimestampRequest& req);
// bool unpack_timestamp_request(const vector<uint8_t>& payload, TimestampRequest& out);
// -> Format: [32 bytes SHA-256 hash]
//
// vector<uint8_t> pack_timestamp_response(const TimestampResponse& res);
// bool unpack_timestamp_response(const vector<uint8_t>& payload, TimestampResponse& out);
// -> Format: [1 byte Status] + [32 bytes Hash] + [8 bytes Unix Timestamp] + [2 bytes Sig Len] + [Signature]
//
// vector<uint8_t> pack_balance_response(const BalanceResponse& res);
// bool unpack_balance_response(const vector<uint8_t>& payload, BalanceResponse& out);
// -> Format: [1 byte Status] + [4 bytes Consumed (nc)] + [4 bytes Remaining (nr)]