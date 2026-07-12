/**
 * common.h - Shared constants and enums used across all modules.
 * 
 * TODO: Define all protocol constants that are not message-struct specific.
 *       This keeps protocol.h focused on serialization.
 */

#ifndef COMMON_H
#define COMMON_H

#include <cstdint>

#define DEFAULT_PORT 8081
#define IP_ADDRESS "127.0.0.1"
#define HASH_LEN 32
#define MAX_MESSAGE_SIZE 65536
#define MAX_DH_PUBKEY_LEN 1024 
#define NONCE_SIZE 32
#define MAX_SIGNATURE_LEN 128

using namespace std;

// TODO: Define Command enum (uint8_t): AUTH, TIMESTAMP, BALANCE - done
enum class Command : uint8_t {
    AUTH = 0x01,
    TIMESTAMP = 0x02,
    BALANCE = 0x03
};

// TODO: Define Status enum (uint8_t): SUCCESS, AUTH_FAILED, INSUFFICIENT_BALANCE, INVALID_COMMAND, INTERNAL_ERROR - done
enum class Status : uint8_t {
    OK                = 0x00,
    AUTH_FAILED       = 0x01,
    QUOTA_EXHAUSTED   = 0x02,
    INVALID_COMMAND   = 0x03,
    INTERNAL_ERROR    = 0x04
};

// Prototipi per la gestione delle connessioni di rete
int server_connection(const char *ip, int port);
int setup_server(int port);

#endif // COMMON_H