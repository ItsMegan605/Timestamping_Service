
#include "../header_files/common.h"
#include "../header_files/crypto.h"
#include <iostream>
using namespace std;


int main(int argc, char* argv[]) {
cout << "Welcome to the service, please connect to the server first" << endl;

int connection = server_connection(IP_ADDRESS,DEFAULT_PORT);
if (connection < 0) {
    cout << "error while connecting to the server" << endl;
}

//handshake with eèhimera keys 
export_public_key() {

}

nonce_generation(){
    
}

}

/**
 * client.cpp - Timestamping Service Client (Main).
 * 
 * TODO: Parse command-line arguments:
 *   - server_ip, port, input_file, username, password.
 * 
 * TODO: Initialize OpenSSL (SSL_library_init, OpenSSL_add_all_algorithms).
 * 
 * TODO: Load the server's connection public key (server_conn_pub.pem) 
 *       and timestamp public key (server_ts_pub.pem) using crypto.h.
 * 
 * TODO: Create a TLS client context using crypto::create_tls_client_ctx().
 * 
 * TODO: Establish a TLS connection to the server using SSL_connect().
 * 
 * TODO: Authenticate:
 *   - Build an AuthRequest, serialize it with protocol::pack_auth_request().
 *   - Send it via protocol::send_message().
 *   - Receive the response, deserialize with protocol::unpack_auth_response().
 *   - If AUTH_FAILED, print error and exit.
 * 
 * TODO: If authentication succeeds:
 *   - Compute SHA-256 of the input file using crypto::sha256_file().
 *   - Build a TimestampRequest, serialize, and send.
 *   - Receive response, deserialize into TimestampResponse.
 *   - If INSUFFICIENT_BALANCE, notify user.
 *   - If SUCCESS, extract the signature and verify it using 
 *     crypto::verify_timestamp(hash, timestamp, signature, server_ts_pub).
 *   - Print the verified timestamp bundle to the console.
 * 
 * TODO: Optionally, send a BALANCE command to show remaining timestamps.
 * 
 * TODO: Close the connection, free SSL objects, clean up.
 */