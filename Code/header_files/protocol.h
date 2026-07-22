/**
 * protocol.h - Defines the exact wire format and serialization functions.
 * TODO: Declare structs for each request/response.
 * TODO: Declare pack() and unpack() functions for each message type.
 *       All integers must be serialized in network byte order (big-endian).
 * 
 * NOTE: All messages are sent over a raw TCP socket (not TLS/SSL).
 *       The payload is already encrypted with AES-GCM before calling send_message().
 *       The send/recv helpers only add a length prefix and handle I/O.
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include "common.h"

using namespace std;


// ---------------------- handshake  ------------------------------

vector<uint8_t> pack_client_hello(const vector<uint8_t>& epub_c, const vector<uint8_t>& nc);
bool unpack_client_hello(const vector<uint8_t>& payload, vector<uint8_t>& out_epub_c, vector<uint8_t>& out_nc);

vector<uint8_t> pack_server_hello(const vector<uint8_t>& epub_s, const vector<uint8_t>& ns, const vector<uint8_t>& signature);
bool unpack_server_hello(const vector<uint8_t>& payload, vector<uint8_t>& out_epub_s, vector<uint8_t>& out_ns, vector<uint8_t>& out_signature);


// ---------- Request Structs ----------
struct AuthRequest {
    string username;
    string password;
};
/* not used for now and //TODO: probably to remove
struct TimestampRequest {
    array<uint8_t, 32> hash;  // SHA-256 hash of the document
};

// (Balance request has no payload, just the command byte)

*/

// ---------- Response Structs ----------
struct AuthResponse {
    Status status; // OK or AUTH_FAILED
};


/* not used for now and //TODO: probably to remove
struct TimestampResponse {
    Status status; // OK, QUOTA_EXHAUSTED, or INTERNAL_ERROR
    array<uint8_t, 32> hash;
    uint64_t timestamp;                // Unix time in seconds (network byte order when sent)
    vector<uint8_t> signature;    // Variable length (DER-encoded ECDSA/RSA signature)
};

struct BalanceResponse {
    Status status; // OK or INTERNAL_ERROR
    uint32_t consumed;
    uint32_t remaining;
};
*/

// ---------- Serialization Functions (pack) ----------
vector<uint8_t> pack_auth_request(const AuthRequest& req);
vector<uint8_t> pack_auth_response(const AuthResponse& res);
/* not used for now and //TODO: probably to remove
vector<uint8_t> pack_timestamp_request(const TimestampRequest& req);
// Balance request is just the command byte, so no pack function needed
*/


// ---------- Deserialization Functions (unpack) ----------
bool unpack_auth_request(const vector<uint8_t>& payload, AuthRequest& out);
bool unpack_auth_response(const vector<uint8_t>& payload, AuthResponse& out);
/*
bool unpack_timestamp_response(const vector<uint8_t>& data, TimestampResponse& out);
bool unpack_balance_response(const vector<uint8_t>& data, BalanceResponse& out);
*/

// ---------- Raw I/O Helpers (over TCP socket, NOT SSL) ----------
bool send_message(int socket_fd, const vector<uint8_t>& payload);
bool recv_message(int socket_fd, vector<uint8_t>& out_payload);
bool send_secure_message(int socket_fd, const vector<uint8_t>& cleartext, const vector<uint8_t>& aes_key, vector<uint8_t>& iv, uint64_t& seq_num);
bool recv_secure_message(int socket_fd, vector<uint8_t>& out_cleartext, const vector<uint8_t>& aes_key, vector<uint8_t>& iv, uint64_t& expected_seq_num);

// -------------- logic functions -----------

vector<uint8_t> getUserBalance();
vector<uint8_t> getUserTimestamp();
vector<uint8_t> userVerification();
#endif // PROTOCOL_H