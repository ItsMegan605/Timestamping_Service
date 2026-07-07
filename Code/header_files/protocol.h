/**
 * protocol.h - Defines the exact wire format and serialization functions.
 * 
 * TODO: Declare structs for each request/response.
 * TODO: Declare pack() and unpack() functions for each message type.
 *       All integers must be serialized in network byte order (big-endian).
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include "common.h"

enum class Status {
    Ok,
    Error
};

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
    Status status;
};

struct TimestampResponse {
    Status status;
    std::array<uint8_t, 32> hash;
    uint64_t timestamp;                // Unix time (seconds)
    std::vector<uint8_t> signature;    // Variable length (RSA or ECDSA)
};

struct BalanceResponse {
    Status status;
    uint32_t consumed;
    uint32_t remaining;
};

// ---------- Serialization Functions ----------
// TODO: std::vector<uint8_t> pack_auth_request(const AuthRequest& req)
// TODO: std::vector<uint8_t> pack_timestamp_request(const TimestampRequest& req)
//       (Balance request is just the command byte, so no pack function needed)

// ---------- Deserialization Functions ----------
// TODO: bool unpack_auth_response(const std::vector<uint8_t>& data, AuthResponse& out)
// TODO: bool unpack_timestamp_response(const std::vector<uint8_t>& data, TimestampResponse& out)
// TODO: bool unpack_balance_response(const std::vector<uint8_t>& data, BalanceResponse& out)

// ---------- I/O Helpers ----------
// TODO: bool send_message(SSL* ssl, const std::vector<uint8_t>& data)
// TODO: bool recv_message(SSL* ssl, std::vector<uint8_t>& out_data)

#endif // PROTOCOL_H