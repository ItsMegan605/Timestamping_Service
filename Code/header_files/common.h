/**
 * common.h - Shared constants and enums used across all modules.
 */

#ifndef COMMON_H
#define COMMON_H

#include <cstdint>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>  
#include <unistd.h> 
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <cstring>
#include <thread>
#include <chrono>
#include <stdlib.h>
#include <mutex>
#include <vector>
#include <fstream>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <iostream>

//Nw and server
#define DEFAULT_PORT 8081
#define IP_ADDRESS "127.0.0.1"
#define MAX_MESSAGE_SIZE 65536

//crypto
#define HASH_LEN 32
#define MAX_DH_PUBKEY_LEN 1024 
#define NONCE_SIZE 32
#define MAX_SIGNATURE_LEN 128

// Parameters AES-GCM
#define IV_SIZE 12             
#define TAG_SIZE 16



enum class Status : uint8_t {
    OK                = 0x00,
    AUTH_FAILED       = 0x01,
    QUOTA_EXHAUSTED   = 0x02,
    INVALID_COMMAND   = 0x03,
    INTERNAL_ERROR    = 0x04
};

int server_connection(const char *ip, int port);
int setup_server(int port);

#endif 