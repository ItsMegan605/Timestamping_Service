/**
 * protocol.cpp - Implements all serialization/deserialization logic.
 * 
 * TODO: For pack functions:
 *   - Use htons(), htonl(), htobe64() for all integers.
 *   - Prepend length prefixes (e.g., uint16_t for strings) where needed.
 *   - Return a flat vector<uint8_t>.
 * 
 * TODO: For unpack functions:
 *   - Verify minimum length.
 *   - Read integers with ntohs(), ntohl(), be64toh().
 *   - Return false if malformed.
 * 
 * TODO: For send_message:
 *   - Prepend the message length as a 4-byte big-endian integer.
 *   - Call SSL_write() in a loop until all bytes are sent.
 * 
 * TODO: For recv_message:
 *   - Read the first 4 bytes to get the payload length.
 *   - Loop SSL_read() until the exact number of bytes is received.
 *   - Return the payload in out_data.
 */

#include "../header_files/protocol.h"
#include <cstring>
#include <stdexcept>

