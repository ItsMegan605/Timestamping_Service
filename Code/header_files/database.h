/**
 * database.h - Manages user accounts with JSON persistence.
 * 
 * TODO: Design a UserDatabase class that:
 *   - Loads users from "data/users.json" using nlohmann/json.
 *   - Authenticates username/password (salted SHA-256).
 *   - Consumes a timestamp (increments consumed, decrements remaining).
 *   - Returns balance (consumed, remaining).
 *   - Saves atomically (write to .tmp, then rename over the original).
 *   - Is thread-safe (mutex for concurrent access).
 */

#ifndef DATABASE_H
#define DATABASE_H

#include <string>
#include <cstdint>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std;


struct UserAccount {
    string username;
    string password_hash;
    string salt;
    unsigned int remaining;
    unsigned int consumed;
    unsigned int total;
};

struct TimestampInfo {
    unsigned int remaining;
    unsigned int consumed;
    unsigned int total;

};


NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(UserAccount, username, password_hash, salt, remaining, consumed, total)

class UserDatabase {
private:
    string db_filepath;
    vector<UserAccount> users;

    void save_to_file();
    string bytes_to_hex(const array<uint8_t, 32>& bytes);

public:
    UserDatabase() = default;

    // Carica i dati dal file JSON
    bool load_from_file(const string& filepath);

    // Verifica le credenziali (SHA256(salt + password))
    bool authenticate(const string& username, const string& password);

    // Ottiene il numero di timestamp
    bool get_balance(const string& username, TimestampInfo& out_info);

    // Decrementa un timestamp e salva su file
    bool consume_timestamp(const string& username);
};

#endif 