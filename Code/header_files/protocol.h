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

// ---------- Request Structs ----------
struct AuthRequest {
    std::string username;
    std::string password;
};

struct TimestampRequest {
    std::array<uint8_t, 32> hash;  // SHA-256 hash of the document
};

// (Balance request has no payload, just the command byte)

// ---------- Response Structs ----------
struct AuthResponse {
    Status status; // OK or AUTH_FAILED
};

struct TimestampResponse {
    Status status; // OK, QUOTA_EXHAUSTED, or INTERNAL_ERROR
    std::array<uint8_t, 32> hash;
    uint64_t timestamp;                // Unix time in seconds (network byte order when sent)
    std::vector<uint8_t> signature;    // Variable length (DER-encoded ECDSA/RSA signature)
};

struct BalanceResponse {
    Status status; // OK or INTERNAL_ERROR
    uint32_t consumed;
    uint32_t remaining;
};

// ---------- Serialization Functions (pack) ----------
std::vector<uint8_t> pack_auth_request(const AuthRequest& req);
std::vector<uint8_t> pack_timestamp_request(const TimestampRequest& req);
// Balance request is just the command byte, so no pack function needed

// ---------- Deserialization Functions (unpack) ----------
bool unpack_auth_response(const std::vector<uint8_t>& data, AuthResponse& out);
bool unpack_timestamp_response(const std::vector<uint8_t>& data, TimestampResponse& out);
bool unpack_balance_response(const std::vector<uint8_t>& data, BalanceResponse& out);

// ---------- Raw I/O Helpers (over TCP socket, NOT SSL) ----------
bool send_message(int socket_fd, const std::vector<uint8_t>& payload);
bool recv_message(int socket_fd, std::vector<uint8_t>& out_payload);

#endif // PROTOCOL_H