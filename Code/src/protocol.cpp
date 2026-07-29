#include "../header_files/protocol.h"
#include "../header_files/crypto.h"
#include "../header_files/interface.h"
#include "../header_files/database.h"
#include "../header_files/common.h"
#include <chrono>
#include <format>
#include <cstring>
#include <iostream>
#include <sys/stat.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h> 
#include <openssl/rand.h>
#include <filesystem>

using namespace std;

// ==============================================================================
// RAW TCP FRAMING FUNCTIONS
// ==============================================================================

//raw send message 
bool send_message(int socket_fd, const vector<uint8_t>& payload) {
    uint32_t payload_len = static_cast<uint32_t>(payload.size());
    if (payload_len > MAX_MESSAGE_SIZE) return false;   

    uint32_t net_len = htonl(payload_len);
    vector<uint8_t> send_buffer;
    send_buffer.reserve(4 + payload_len);

    // Safely copy the 4-byte length into the buffer
    uint8_t len_bytes[4];
    memcpy(len_bytes, &net_len, 4);
    send_buffer.insert(send_buffer.end(), len_bytes, len_bytes + 4);
    
    // Append the actual payload
    send_buffer.insert(send_buffer.end(), payload.begin(), payload.end());

    size_t total_sent = 0;
    const size_t total_to_send = send_buffer.size();

    // Loop until all bytes are transmitted (handles TCP fragmentation)
    while (total_sent < total_to_send) {
        ssize_t bytes_sent = send(socket_fd, send_buffer.data() + total_sent, total_to_send - total_sent, 0);
        if (bytes_sent <= 0) return false;
        total_sent += static_cast<size_t>(bytes_sent);
    }
    return true;
}

//raw receive message
bool recv_message(int socket_fd, vector<uint8_t>& out_payload) {
    uint8_t len_buf[4];
    size_t total_received = 0;

    //Read the 4-byte length header
    while (total_received < 4) {
        ssize_t bytes_recv = recv(socket_fd, len_buf + total_received, 4 - total_received, 0);
        if (bytes_recv <= 0) return false;
        total_received += static_cast<size_t>(bytes_recv);
    }

    uint32_t net_len;
    memcpy(&net_len, len_buf, 4);
    uint32_t payload_len = ntohl(net_len);

    if (payload_len == 0) {
        out_payload.clear();
        return true;
    }
    
    //Security check: drop excessively large messages
    if (payload_len > MAX_MESSAGE_SIZE) return false;

    out_payload.resize(payload_len);
    total_received = 0;

    //Read exactly payload_len bytes from the socket
    while (total_received < payload_len) {
        ssize_t bytes_recv = recv(socket_fd, out_payload.data() + total_received, payload_len - total_received, 0);
        if (bytes_recv <= 0) return false;
        total_received += static_cast<size_t>(bytes_recv);
    }
    return true;
}


//Serializes the Client Hello parameters.
//Format: [2 bytes key len] + [Epub_C] + [Nonce_C]
vector<uint8_t> pack_client_hello(const vector<uint8_t>& epub_c, const vector<uint8_t>& nc) {
    vector<uint8_t> buffer;
    
    //allocation of exact memory
    buffer.reserve(epub_c.size() + nc.size());
    buffer.insert(buffer.end(), epub_c.begin(), epub_c.end());
    buffer.insert(buffer.end(), nc.begin(), nc.end());
    
    return buffer;
}

//Deserializes the Client Hello parameters, verifying strict boundaries.
bool unpack_client_hello(const vector<uint8_t>& payload, vector<uint8_t>& out_epub_c, vector<uint8_t>& out_nc) {
    const size_t EPH_KEY_SIZE = 91; //perfect dimention
    
    if (payload.size() != EPH_KEY_SIZE + NONCE_SIZE) return false;
    
    
    out_epub_c.assign(payload.begin(), payload.begin() + EPH_KEY_SIZE);
    out_nc.assign(payload.begin() + EPH_KEY_SIZE, payload.end());
    
    return true;
}


//Serializes the Server Hello parameters.
// Current Format: [Epub_S] + [Nonce_S] + [Signature]
vector<uint8_t> pack_server_hello(const vector<uint8_t>& epub_s, const vector<uint8_t>& ns, const vector<uint8_t>& signature) {
    vector<uint8_t> buffer;
    
    buffer.insert(buffer.end(), epub_s.begin(), epub_s.end());
    buffer.insert(buffer.end(), ns.begin(), ns.end());
    buffer.insert(buffer.end(), signature.begin(), signature.end());
    
    return buffer;
}

//Deserializes the Server Hello parameters sequentially using an offset tracker.
bool unpack_server_hello(const vector<uint8_t>& payload, vector<uint8_t>& out_epub_s, vector<uint8_t>& out_ns, vector<uint8_t>& out_signature) {
    const size_t EPH_KEY_SIZE = 91;
    size_t offset = 0;

    if (payload.size() < EPH_KEY_SIZE + NONCE_SIZE) return false; 

    out_epub_s.assign(payload.begin() + offset, payload.begin() + offset + EPH_KEY_SIZE);
    offset += EPH_KEY_SIZE;

    out_ns.assign(payload.begin() + offset, payload.begin() + offset + NONCE_SIZE);
    offset += NONCE_SIZE;

    size_t sig_len = payload.size() - offset;
    out_signature.assign(payload.begin() + offset, payload.end());
    
    return true;
}

// Serializes the authentication credentials.
// Format: [2 bytes username len] + [username] + [2 bytes password len] + [password]

vector<uint8_t> pack_auth_request(const AuthRequest& req) {
    vector<uint8_t> out;

    uint16_t username_len = static_cast<uint16_t>(req.username.size());
    uint16_t password_len = static_cast<uint16_t>(req.password.size());

    uint16_t username_len_net = htons(username_len);
    uint16_t password_len_net = htons(password_len);
    
    uint8_t len_bytes[2];
    
    // Pack username
    memcpy(len_bytes, &username_len_net, 2);
    out.insert(out.end(), len_bytes, len_bytes + 2);
    out.insert(out.end(), req.username.begin(), req.username.end());

    // Pack password
    memcpy(len_bytes, &password_len_net, 2);
    out.insert(out.end(), len_bytes, len_bytes + 2);
    out.insert(out.end(), req.password.begin(), req.password.end());
    
    return out;
}

// Deserializes the authentication credentials, protecting against invalid lengths.
bool unpack_auth_request(const vector<uint8_t>& payload, AuthRequest& out) {
    if (payload.size() < 4) return false; 
    
    const uint16_t MAX_USERNAME_LEN = 64; 
    const uint16_t MAX_PASSWORD_LEN = 128; 

    size_t offset = 0;

    // read username length
    uint16_t username_len_net;
    memcpy(&username_len_net, payload.data() + offset, 2);
    offset += 2;
    uint16_t username_len = ntohs(username_len_net);

    if (username_len == 0 || username_len > MAX_USERNAME_LEN) return false;
    if (payload.size() < offset + username_len + 2) return false; 

    // extract username
    out.username.assign(payload.begin() + offset, payload.begin() + offset + username_len);
    offset += username_len;

    // read password length
    uint16_t password_len_net;
    memcpy(&password_len_net, payload.data() + offset, 2);
    offset += 2;
    uint16_t password_len = ntohs(password_len_net);

    if (password_len == 0 || password_len > MAX_PASSWORD_LEN) return false;
    if (payload.size() < offset + password_len) return false;

    // extract password
    out.password.assign(payload.begin() + offset, payload.begin() + offset + password_len);
    return true;
}

//Serializes the authentication response. It is a single byte representing the Status enum.
vector<uint8_t> pack_auth_response(const AuthResponse& res) {
    return vector<uint8_t>{static_cast<uint8_t>(res.status)};
}

//Deserializes the authentication response, validating the Status enum range.
bool unpack_auth_response(const vector<uint8_t>& payload, AuthResponse& out) {
    if (payload.size() != 1) return false; 
    
    uint8_t status_byte = payload[0];
    if (status_byte > static_cast<uint8_t>(Status::INTERNAL_ERROR)) return false;
    
    out.status = static_cast<Status>(payload[0]);
    return true;
}

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <iostream>

using namespace std;


bool send_secure_message(int socket_fd, const vector<uint8_t>& cleartext, const vector<uint8_t>& aes_key, uint64_t& send_seq_num) {
    
    //calculate max pt dimention to not overflow the dimention
    const size_t MAX_PLAINTEXT_SIZE = MAX_MESSAGE_SIZE - IV_SIZE - TAG_SIZE;

//control to avoiud buffer overflow
    if (cleartext.empty() || cleartext.size() > MAX_PLAINTEXT_SIZE) {
        cerr << "[ERROR] CAN'T ENCRYPT, INVALID INPUT PARAMETERS! Payload size: " 
            << cleartext.size() << " bytes." << endl;
        return false;
    }

    size_t mess_len = cleartext.size(); 
    
    vector<uint8_t> payload_buffer(IV_SIZE + mess_len + TAG_SIZE);
    unsigned char* iv = payload_buffer.data();
    unsigned char* ciphertext = payload_buffer.data() + IV_SIZE;
    unsigned char* tag = payload_buffer.data() + IV_SIZE + mess_len;

    //Generate the IV directly in the dedicated memory portion
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        cerr << "[ERROR] IV generation failed." << endl;
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    //Insert Sequence Number as AAD (Additional Authenticated Data)
    if (EVP_EncryptUpdate(ctx, NULL, &len, reinterpret_cast<const unsigned char*>(&send_seq_num), sizeof(send_seq_num)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    //Direct encryption into the "ciphertext" portion of the buffer
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, cleartext.data(), mess_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    //Extract the TAG directly into the tail of the buffer
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    
    send_seq_num++; //Increment to prevent replay attacks

    //Send the fully assembled contiguous buffer
    return send_message(socket_fd, payload_buffer);
}

bool recv_secure_message(int socket_fd, vector<uint8_t>& cleartext_out, const vector<uint8_t>& aes_key, uint64_t& recv_seq_num) {
    vector<uint8_t> recv_buffer;
    
    //Receive the complete payload
    if (!recv_message(socket_fd, recv_buffer)) {
        cerr << "[ERROR] Reception failed or socket closed." << endl;
        return false;
    }
    
    if (recv_buffer.size() < IV_SIZE + TAG_SIZE) {
        cerr << "[ERROR] Received payload is too short." << endl;
        return false;
    }

    int payload_len = static_cast<int>(recv_buffer.size() - IV_SIZE - TAG_SIZE);
    
    //Map pointers to their respective sections in the received buffer
    unsigned char* iv = recv_buffer.data();
    unsigned char* ciphertext = recv_buffer.data() + IV_SIZE;
    unsigned char* tag = recv_buffer.data() + IV_SIZE + payload_len;

    //Pre-allocate the output buffer
    cleartext_out.resize(payload_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    //Insert Sequence Number (AAD) for verification
    if (EVP_DecryptUpdate(ctx, NULL, &len, reinterpret_cast<const unsigned char*>(&recv_seq_num), sizeof(recv_seq_num)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    //Decryption
    if (EVP_DecryptUpdate(ctx, cleartext_out.data(), &len, ciphertext, payload_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    //Set the received TAG to allow OpenSSL to validate it
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    //Finalization. In GCM, this step performs TAG authentication!
    int ret = EVP_DecryptFinal_ex(ctx, cleartext_out.data() + plaintext_len, &len);
    
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) {
        cerr << "[CRITICAL ERROR] Decryption failed! TAG mismatch (Possible MitM, Replay, or Data Corruption)." << endl;
        cleartext_out.clear(); //Memory cleanup
        return false;
    }

    recv_seq_num++;
    return true;
}

// ------------------------------------------------------------
// USER BALANCE REQ
// ----------------------------------
void getUserBalance(int sock, const vector<uint8_t>& aes_key, uint64_t& send_seq_num, uint64_t& recv_seq_num) {
    
    printBanner("Balance request submitted. Here is your balance:", BOLD_MAGENTA);
    cout << "Server request loading... \n";

    //Send command byte 'B' over the secure AES-GCM channel
    vector<uint8_t> request_payload = {'B'}; 

    //send_secure_message handles AES encryption and sequence number (seq_num) increment
    //to protect the transmission against both eavesdropping and replay attacks.
    if (!send_secure_message(sock, request_payload, aes_key, send_seq_num)) {
        cerr << "[CLIENT ERROR] Error sending balance request!" << endl;
        return; 
    }

    //Receive encrypted payload from server
    vector<uint8_t> response_payload;

    if (!recv_secure_message(sock, response_payload, aes_key, recv_seq_num)) {
        cerr << "[CLIENT ERROR] Error receiving response from server!" << endl;
        return;
    }

    //Unpack & decrypt binary payload into C++ struct
    BalanceResponse res;

    //We pass the raw decrypted bytes to the unpacking function to safely rebuild our struct
    //avoiding any padding or memory alignment issues.
    if (!unpack_balance_response(response_payload, res)) {
        cerr << "[CLIENT ERROR] Invalid balance response format!" << endl;
        return;
    }

    //Validate server status
    if (res.status != Status::OK) {
        cerr << "[CLIENT ERROR] Server failed to retrieve balance." << endl;
        return;
    }

    cout << "Here is the server Response!!" << endl;
    
    //Render populated data to screen
    balance(res.info); 
}

vector<uint8_t> pack_balance_response(const BalanceResponse& res) {
    vector<uint8_t> out;
    
    //Pre-allocate memory to avoid multiple reallocations during push_back/insert.
    //Size is strictly 13 bytes: 1 (status) + 4 (consumed) + 4 (remaining) + 4 (total).
    out.reserve(13); 

    //Response status (1 byte)
    out.push_back(static_cast<uint8_t>(res.status));

    // Handle Endianness for 32-bit integers
    uint32_t consumed_net = htonl(static_cast<uint32_t>(res.info.consumed));
    uint32_t remaining_net = htonl(static_cast<uint32_t>(res.info.remaining));
    uint32_t total_net = htonl(static_cast<uint32_t>(res.info.total));

    //Insert the 4-byte fields into the buffer
    uint8_t buf[4];
    
    memcpy(buf, &consumed_net, 4);
    out.insert(out.end(), buf, buf + 4);

    memcpy(buf, &remaining_net, 4);
    out.insert(out.end(), buf, buf + 4);

    memcpy(buf, &total_net, 4);
    out.insert(out.end(), buf, buf + 4);

    return out;
}

bool unpack_balance_response(const vector<uint8_t>& payload, BalanceResponse& out) {
    // Strict security check on exact payload size.
    if (payload.size() != 13) return false;

    //Extract status byte
    uint8_t status_byte = payload[0];
    
    //Basic bounds checking to ensure the status byte represents a valid ENUM value
    if (status_byte > static_cast<uint8_t>(Status::INTERNAL_ERROR)) return false;
    out.status = static_cast<Status>(status_byte);

    //Extract consumed, remaining, and total fields
    uint32_t consumed_net, remaining_net, total_net;

    // Read bytes 1 to 4
    memcpy(&consumed_net, payload.data() + 1, 4);
    out.info.consumed = ntohl(consumed_net);

    //Read bytes 5 to 8
    memcpy(&remaining_net, payload.data() + 5, 4);
    out.info.remaining = ntohl(remaining_net);

    //Read bytes 9 to 12
    memcpy(&total_net, payload.data() + 9, 4);
    out.info.total = ntohl(total_net);

    return true;
}

//--------------------------------------------------
// TIMESTAMPING 
//--------------------------------------
void getUserTimestamp(int sock, const vector<uint8_t>& aes_key, uint64_t& send_seq_num, uint64_t& recv_seq_num) {
    //Initialize the payload with the command byte 'T', also for the server
    vector<uint8_t> request_payload = {'T'}; 

    printBanner("Timestamp request submitted.", BOLD_CYAN);
    
    //getting the file name to timestamp
    std::string filename;
    cout << "Enter the name of the file you want to timestamp: ";
    cin >> filename;

    //INPUT VALIDATION
    if(filename.empty()) {
        cerr << "[CLIENT ERROR] Filename cannot be empty." << endl;
        return;
    }
    
    //Prevent Path Traversal attacks
    if(filename.find('/') != string::npos || filename.find('\\') != string::npos || filename.find("..") != string::npos) {
        cerr << "[CLIENT ERROR] please enter the filename not the path" << endl;
        return;
    }
    
    //Automatically append ".txt" extension if the user didn't provide one
    if (filename.find('.') == string::npos) {
        filename += ".txt";
    }
    
    //Define  paths for input and output directories
    string inputFolder = "../timestamp_docs";
    string outputFolder = "../timestamped_docs";
    string fullPath = inputFolder + "/" + filename; 
    
    // Estrai il nome pulito senza estensione anche per la fase di lettura
    string baseNameVerify = std::filesystem::path(filename).stem().string();
    string jsonFilePath = outputFolder + "/" + baseNameVerify + ".json";
    //HASH COMPUTATION
    array<uint8_t, 32> hash = sha256_file(fullPath); //shaof the local file
    
    //Check if the hash is all zeros, which indicates the file reading or hashing failed
    if(hash[0] == 0 && hash[1] == 0 && hash[2] == 0 && hash[3] == 0) {
        cerr << "[CLIENT ERROR] Failed to compute SHA-256 hash of the file." << endl;
        return;
    }

    //BUILD AND SEND REQUEST
    // Create the request object and pack it into a byte array for network transmission
    TimestampRequest req;
    req.hash = hash;
    vector<uint8_t> ts_payload = pack_timestamp_request(req);
    
    //Append the packed hash to the initial 'T' command byte
    request_payload.insert(request_payload.end(), ts_payload.begin(), ts_payload.end());
    
    //Send the request securely with the secure send
    if (!send_secure_message(sock, request_payload, aes_key, send_seq_num)) {
        cerr << "[CLIENT ERROR] Error sending timestamp request!" << endl;
        return;
    }

    //RECEIVE AND UNPACK RESPONSE ---
    vector<uint8_t> response_payload;
    if (!recv_secure_message(sock, response_payload, aes_key, recv_seq_num)) {
        cerr << "[CLIENT ERROR] Error receiving timestamp response!" << endl;
        return;
    }

    //Deserialize the raw bytes back into a structured TimestampResponse object
    TimestampResponse resp;
    if (!unpack_timestamp_response(response_payload, resp)) {
        cerr << "[CLIENT ERROR] Invalid timestamp response format!" << endl;
        return;
    }

    //Check if the server processed the request successfully
    if (resp.status != Status::OK) {
        cerr << "[CLIENT ERROR] Server failed to provide timestamp." << endl;
        return;
    }

    //CRYPTOGRAPHIC VERIFICATION
    // Load the server's public key to verify that the timestamp was actually generated by the server
    EVP_PKEY* ts_pubk = load_public_key("../keys/server_ts_pub.pem");
    if (!ts_pubk) {
        cerr << "[CLIENT ERROR] Failed to load timestamp public key." << endl;
        return;
    }

    //Reconstruct the exact data that the server signed: [32-byte hash] + [8-byte timestamp]
    vector<uint8_t> signed_data(40);
    memcpy(signed_data.data(), resp.hash.data(), 32); // Copy the hash
    
    //Convert timestamp to Network Byte Order (Big-Endian) before checking the signature.
    uint64_t ts_net = htobe64(resp.timestamp);
    memcpy(signed_data.data() + 32, &ts_net, 8); //Append the timestamp

    //Verify the digital signature using the constructed data and the server's public key
    bool valid_sig = verify_signature(signed_data, resp.signature, ts_pubk);
    EVP_PKEY_free(ts_pubk); // Free memory to prevent leaks

    //PROCESS AND SAVE RESULTS
    if (valid_sig) {
        // Convert the 32-byte hash into a readable hexadecimal string
        string Hash_Value;
        for(uint8_t byte : resp.hash) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            Hash_Value += buf;
        }

        //Convert the digital signature into a readable hexadecimal string for JSON storage and display
        string Signature;
        for(uint8_t byte : resp.signature) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            Signature += buf;
        }
        
        timestampCompleted(filename, Hash_Value, resp.timestamp, Signature);

        //Build a JSON object to store the timestamp metadata persistently and save them
        json jsonTimestamp;
        jsonTimestamp["Hash Value"] = Hash_Value;
        jsonTimestamp["Timing"] = to_string(resp.timestamp);
        jsonTimestamp["Signature"] = Signature;
        
        if(mkdir(outputFolder.c_str(), 0755) != 0 && errno != EEXIST) {
            cerr << "[CLIENT ERROR] Failed to create output folder." << endl;
            return;
        }

        //Open the JSON file and write the data
        ofstream jsonFile(jsonFilePath);
        if (!jsonFile.is_open()) {
            cerr << "[CLIENT ERROR] Failed to open JSON file for writing."<< endl;
            return;
        }
        
        //Dump the JSON with an indentation of 4 spaces for better readability
        jsonFile << jsonTimestamp.dump(4);
        jsonFile.close();
        
        cout << "[CLIENT] JSON information successfully saved in: " << jsonFilePath << endl;
    } else {
        printBanner("[CLIENT ERROR] Timestamp VERIFICATION FAILED!", BOLD_RED);
    }
}

//Converts a TimestampRequest struct into a raw byte array for network transmission
vector<uint8_t> pack_timestamp_request(const TimestampRequest& req) {
    vector<uint8_t> out(32);
    // Copy the 32 bytes of the hash into the output vector
    memcpy(out.data(), req.hash.data(), 32); 
    return out;
}

//Converts a raw byte array received from the network back into a TimestampRequest struct
bool unpack_timestamp_request(const vector<uint8_t>& payload, TimestampRequest& out) {
    // The request payload must be exactly 32 bytes (the SHA-256 hash size)
    if (payload.size() != 32) return false;
    memcpy(out.hash.data(), payload.data(), 32);
    return true;
}

//Converts a TimestampResponse struct into a raw byte array, handling Endianness
vector<uint8_t> pack_timestamp_response(const TimestampResponse& res) {
    vector<uint8_t> out;

    //Status (1 byte)
    out.push_back(static_cast<uint8_t>(res.status));
    
    //Hash (32 bytes)
    out.insert(out.end(), res.hash.begin(), res.hash.end());
    
    //Timestamp (8 bytes). 
    // htobe64 converts the 64-bit integer from Host byte order to Network byte order (Big-Endian)
    uint64_t ts_net = htobe64(res.timestamp);
    uint8_t ts_bytes[8];
    memcpy(ts_bytes, &ts_net, 8);
    out.insert(out.end(), ts_bytes, ts_bytes + 8);
    
    out.insert(out.end(), res.signature.begin(), res.signature.end());
    
    return out;
}

//Converts a raw byte array received from the network back into a TimestampResponse struct
bool unpack_timestamp_response(const vector<uint8_t>& payload, TimestampResponse& out) {
    // Check if the payload has at least the minimum required size: 
    // 1 (status) + 32 (hash) + 8 (timestamp)  = 41 bytes
    if (payload.size() < 1 + 32 + 8) return false; 

    size_t offset = 0;
    
    //Read Status
    uint8_t status_byte = payload[offset++];
    if (status_byte > static_cast<uint8_t>(Status::INTERNAL_ERROR)) return false; // Basic bounds checking
    out.status = static_cast<Status>(status_byte);
    
    //Read Hash
    memcpy(out.hash.data(), payload.data() + offset, 32);
    offset += 32;
    
    //Read Timestamp
    uint64_t ts_net;
    memcpy(&ts_net, payload.data() + offset, 8);
    out.timestamp = be64toh(ts_net);
    offset += 8;
    
    out.signature.assign(payload.begin() + offset, payload.end());

    return true;
}

//------------------------------------------------------
// Verification function - local within the service
//------------------------------------------------------

void userVerification(int sock, const vector<uint8_t>& aes_key) {

    printBanner("Let's verify your timestamp.", BOLD_GREEN);

    string fileToVerify;
    cout << "Plase insert the name of the file that you want to verify: \n" << endl;
    
    cin >> fileToVerify;

    if (fileToVerify.empty()){
        cerr << "ERROR: the file is empty and cannot be verified." << endl;
        return;
    }

    if (fileToVerify.find('/') != string::npos){
        cerr << "ERROR: please insert only the file name, not the path." << endl;
        return;
    }

    if (fileToVerify.find('.') == string::npos) {
        fileToVerify += ".txt";
    }


    string inputFolder = "../timestamp_docs";
    string outputFolder = "../timestamped_docs";
    string fullPath = inputFolder + "/" + fileToVerify; 
    
    string baseNameVerify = std::filesystem::path(fileToVerify).stem().string();
    string jsonFilePath = outputFolder + "/" + baseNameVerify + ".json";
    
    cout << "Calculating the hash of the file..." << endl;

    array<uint8_t, 32> currentHashFile = sha256_file(fullPath);
    if (currentHashFile[0] == 0 && currentHashFile[1] == 0 && currentHashFile[2] == 0 && currentHashFile[3] == 0){
        cerr << "Error in finding or reading the file" << endl;
        return;
    }
    ifstream fileStream(jsonFilePath);
    if(!fileStream.is_open()) {
        cerr << "the document hasn't been timestamped yet, sorry." << endl;
        return;
    }
    //parsing json
    json jsonTimestamp;
    try {
        fileStream >> jsonTimestamp;
    } catch (const json::parse_error& ex) {
        printBanner("The file was corrupted or wrong!", BOLD_RED);
        return;
    }
    fileStream.close();

    string hash; //expected hash 
    string time;
    string signature;

    try{
        hash = jsonTimestamp.at("Hash Value").get<string>();
        time = jsonTimestamp.at("Timing").get<string>();
        signature = jsonTimestamp.at("Signature").get<string>();

    } catch (const exception& e){
        cerr << "The document hash wrong or missing fields!" << endl;
        return;
    }

char hexBuffer[65]; 
    for (int i = 0; i < 32; i++) {
        snprintf(&hexBuffer[i * 2], 3, "%02x", currentHashFile[i]); 
    }
    string currentHashHex(hexBuffer);

    if (currentHashHex != hash) {
        printBanner("THE FILE WAS MODIFIED: the current hash doesn't correspond with the original one!\n", BOLD_RED);
        return;
    } 
    
    printBanner("The file was not altered, nice job mate. Proceeding with signature verification...", BOLD_GREEN);
    

    vector<uint8_t> signatureBinary;
    try {
        for (size_t i = 0; i < signature.length(); i += 2) {
            signatureBinary.push_back(static_cast<uint8_t>(stoul(signature.substr(i, 2), nullptr, 16)));
        }
    } catch (const exception& e) {
        cerr << "[CLIENT ERROR] Invalid signature format in JSON document." << endl;
        return;
    }
    vector<uint8_t> dataToVerify(40);
    memcpy(dataToVerify.data(), currentHashFile.data(), 32); 
    
    uint64_t ts_net = htobe64(stoull(time)); // Converte il tempo di nuovo in network byte order
    memcpy(dataToVerify.data() + 32, &ts_net, 8); 

    EVP_PKEY* ts_pubk = load_public_key("../keys/server_ts_pub.pem");
    if (!ts_pubk) {
        cerr << "Error: impossible to load the public key for verification." << endl;
        return;
    }

    bool isValid = verify_signature(dataToVerify, signatureBinary, ts_pubk);
    EVP_PKEY_free(ts_pubk);

    if (isValid) {
        printBanner("Verification completed: The timestamp is VALID and AUTHENTIC!", BOLD_GREEN);
        verificationCompleted(time);
    } else {
        printBanner("CRYPTOGRAPHIC ERROR: The server signature does not match! The JSON was forged.", BOLD_RED);
    }
}


//for printing the correct timetsamp format 
void printTimestampOf(const unsigned char* doc) {
    // 1. Estraiamo gli 8 byte del timestamp in secondi (Unix time) dal buffer
    uint64_t raw_timestamp = 0;
    
    // Assicurati che HASH_SIZE sia 32. L'offset è subito dopo l'hash.
    // (Se il tuo pacchetto include lo status byte all'inizio, tieni conto dell'offset + 1)
    size_t offset = 32; // HASH_SIZE
    memcpy(&raw_timestamp, doc + offset, sizeof(uint64_t));
    
    // Se il timestamp era stato salvato in Network Byte Order, lo riconvertiamo in Host
    uint64_t host_timestamp = be64toh(raw_timestamp);

    // 2. Convertiamo i secondi in una time_point di tipo system_clock
    std::chrono::seconds duration_secs(host_timestamp);
    std::chrono::system_clock::time_point tp(duration_secs);
    
    // 3. Formattiamo stampando l'orario locale usando C++20 chrono e zoned_time
    auto local_time = std::chrono::zoned_time{chrono::current_zone(), tp};
    std::cout << std::format("{:%Y-%m-%d %H:%M:%S}", local_time) << '\n';
}