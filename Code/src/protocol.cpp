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

