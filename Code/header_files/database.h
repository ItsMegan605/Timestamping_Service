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
#include <unordered_map>
#include <mutex>
#include <cstdint>

struct UserAccount {
    std::string password_hash;  // hex string
    std::string salt;           // hex string
    uint32_t total_purchased;
    uint32_t consumed;
};

class UserDatabase {
public:
    UserDatabase() = default;
    ~UserDatabase() = default;

    // TODO: bool load_from_file(const std::string& path = "data/users.json")
    // TODO: bool save_to_file(const std::string& path = "data/users.json") 

    // TODO: bool authenticate(const std::string& username, const std::string& password) const
    // TODO: bool consume_timestamp(const std::string& username)  // returns false if quota exhausted
    // TODO: void get_balance(const std::string& username, uint32_t& consumed, uint32_t& remaining) const

private:
    std::unordered_map<std::string, UserAccount> accounts_;
    mutable std::mutex mtx_;   // protects accounts_ during concurrent ops
    std::string current_file_;
};

#endif // DATABASE_H
