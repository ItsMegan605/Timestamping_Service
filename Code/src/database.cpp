/**
 * database.cpp - Implements JSON-based user database.
 * 
 * TODO: Include nlohmann/json.hpp (single header).
 * 
 * TODO: load_from_file():
 *   - Lock mutex.
 *   - Open the JSON file, parse it.
 *   - Iterate over "users" object, extract fields.
 *   - Store in accounts_ map.
 *   - If main file missing, try "users_backup.json".
 * 
 * TODO: save_to_file():
 *   - Build a JSON object from accounts_.
 *   - Write to "users.json.tmp".
 *   - Optionally call fsync() on the tmp file descriptor.
 *   - Rename "users.json.tmp" -> "users.json" (this is atomic on POSIX systems).
*    - Do NOT rename the original to a backup first – that can cause data loss.
 *   - (Optional: keep a separate backup by copying the old file before writing).
 * 
 * TODO: authenticate():
 *   - Look up username. If not found, return false.
 *   - Compute SHA-256(password + salt). Compare with stored hash (use constant-time compare).
 * 
 * TODO: consume_timestamp():
 *   - Lock mutex, check if consumed < total_purchased.
 *   - If yes, increment consumed, call save_to_file(), return true.
 *   - Else return false.
 * 
 * TODO: get_balance():
 *   - Lock mutex, return consumed and (total_purchased - consumed).
 */

#include "../header_files/database.h"
//#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

//using json = nlohmann::json;

