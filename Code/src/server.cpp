/**
 * server.cpp - Timestamping Service Server (Main).
 * 
 * TODO: Parse command-line arguments (port, database path).
 * 
 * TODO: Initialize OpenSSL globally.
 * 
 * TODO: Load the UserDatabase from "data/users.json" using database.h.
 * 
 * TODO: Load server private keys:
 *   - privKc (server_conn_priv.pem) for TLS.
 *   - privKts (server_ts_priv.pem) for signing timestamps.
 * 
 * TODO: Create a TLS server context using crypto::create_tls_server_ctx()
 *       (load the certificate and privKc into it).
 * 
 * TODO: Create a listening socket (bind + listen) on the specified port.
 * 
 * TODO: Enter an infinite loop:
 *   - Accept a new client connection (SSL_accept).
 *   - For each client, spawn a std::thread to handle it.
 * 
 * In the client handler function:
 *   - TODO: Receive and deserialize an AuthRequest.
 *   - TODO: Call db.authenticate(username, password).
 *   - TODO: If fails, send AUTH_FAILED status and close.
 *   - TODO: If success, send SUCCESS status.
 *   - TODO: Then loop to process commands:
 *       - Read the command byte (protocol::recv_message).
 *       - If TIMESTAMP:
 *           - Read 32 bytes (hash).
 *           - Call db.consume_timestamp(username).
 *           - If insufficient, send INSUFFICIENT_BALANCE (with hash echoed).
 *           - Else, get current time (uint64_t).
 *           - Sign (hash || time) with privKts using crypto::sign_timestamp().
 *           - Build TimestampResponse and send it.
 *       - If BALANCE:
 *           - Call db.get_balance(), build BalanceResponse, send it.
 *       - If invalid command, send INVALID_COMMAND.
 *   - When client disconnects, close SSL and exit thread.
 * 
 * TODO: Join all threads on shutdown (or detach them).
 */

#include <thread>
#include <vector>
#include <iostream>
//...


int main(int argc, char* argv[]) {
    // TODO: Parse args, init, listen, accept threads
    return 0;
}