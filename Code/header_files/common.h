/**
 * common.h - Shared constants and enums used across all modules.
 * 
 * TODO: Define all protocol constants that are not message-struct specific.
 *       This keeps protocol.h focused on serialization.
 */

#ifndef COMMON_H
#define COMMON_H

#include <cstdint>

#define DEFAULT_PORT 8080
#define IP_ADDRESS "127.0.0.0"
#define HASH_LEN 32
#define MAX_MESSAGE_SIZE 65536

// TODO: Define Command enum (uint8_t): AUTH, TIMESTAMP, BALANCE
// TODO: Define Status enum (uint8_t): SUCCESS, AUTH_FAILED, INSUFFICIENT_BALANCE, INVALID_COMMAND, INTERNAL_ERROR

#endif // COMMON_H