/**
 * protocol.h - Defines the exact wire format and serialization functions.
 * 
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
// TODO: std::vector<uint8_t> pack_request(Command cmd, const void* req_struct)
//       or explicit: pack_auth_request, pack_timestamp_request.
//       The first byte of the returned payload must be the Command value.
//       All integers converted to network byte order (htons, htonl, htobe64).
// TODO: std::vector<uint8_t> pack_auth_request(const AuthRequest& req)
// TODO: std::vector<uint8_t> pack_timestamp_request(const TimestampRequest& req)
//       (Balance request is just the command byte, so no pack function needed)

// ---------- Deserialization Functions (unpack) ----------
// TODO: bool unpack_auth_response(const std::vector<uint8_t>& data, AuthResponse& out)
// TODO: bool unpack_timestamp_response(const std::vector<uint8_t>& data, TimestampResponse& out)
// TODO: bool unpack_balance_response(const std::vector<uint8_t>& data, BalanceResponse& out)
//       Each must verify minimum length and convert from network to host byte order.

// ---------- Raw I/O Helpers (over TCP socket, NOT SSL) ----------
// TODO: bool send_message(int socket_fd, const std::vector<uint8_t>& payload)
//       - Prepend a 4-byte big-endian length (payload size).
//       - Send the length + payload using send() in a loop until all bytes sent.
// TODO: bool recv_message(int socket_fd, std::vector<uint8_t>& out_payload)
//       - Read the first 4 bytes to get the length.
//       - Loop recv() until the exact number of payload bytes is received.
//       - Return the payload in out_payload.

#endif // PROTOCOL_H