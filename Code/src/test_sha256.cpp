/**
 * test_sha256.cpp - Standalone test harness for SHA-256 hashing functions.
 * 
 * Tests:
 * 1. SHA-256 of empty string (known vector).
 * 2. SHA-256 of "Hello" (known vector).
 * 3. SHA-256 of a file (optional – create test.txt with "Hello").
 * 4. SHA-256 of password+salt (simulating database use).
 */

#include "../header_files/crypto.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <string>
#include <cstdlib>

using namespace std;

// Helper function to print a hash as hex
void print_hash(const array<uint8_t, 32>& hash, const string& label) {
    cout << label << ": ";
    for (uint8_t byte : hash) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    cout << dec << endl; // Reset to decimal
}

// Helper to compare two hashes
bool hashes_equal(const array<uint8_t, 32>& a, const array<uint8_t, 32>& b) {
    for (size_t i = 0; i < 32; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

int main() {
    cout << "\n========================================" << endl;
    cout << "        SHA-256 Test Harness            " << endl;
    cout << "========================================\n" << endl;

    bool all_tests_passed = true;

    // ============================================================
    // Test 1: Empty string (known test vector)
    // ============================================================
    cout << "[Test 1] SHA-256 of empty string" << endl;
    vector<uint8_t> empty_data;
    array<uint8_t, 32> hash_empty = sha256_data(empty_data);
    print_hash(hash_empty, "  Result");

    // Expected SHA-256 of empty string (from NIST)
    array<uint8_t, 32> expected_empty = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    if (hashes_equal(hash_empty, expected_empty)) {
        cout << "  PASSED" << endl;
    } else {
        cout << "  FAILED" << endl;
        cout << "  Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" << endl;
        all_tests_passed = false;
    }
    cout << endl;

    // ============================================================
    // Test 2: "Hello" (known test vector)
    // ============================================================
    cout << "[Test 2] SHA-256 of \"Hello\"" << endl;
    string hello_str = "Hello";
    array<uint8_t, 32> hash_hello = sha256_data(hello_str);
    print_hash(hash_hello, "  Result");

    // Expected SHA-256 of "Hello" (from online calculators)
    array<uint8_t, 32> expected_hello = {
        0x18, 0x5f, 0x8d, 0xb3, 0x22, 0x71, 0xfe, 0x25,
        0xf5, 0x61, 0xa6, 0xfc, 0x93, 0x8b, 0x2e, 0x26,
        0x43, 0x06, 0xec, 0x30, 0x4e, 0xda, 0x51, 0x80,
        0x07, 0xd1, 0x76, 0x48, 0x26, 0x38, 0x19, 0x69
    };

    if (hashes_equal(hash_hello, expected_hello)) {
        cout << " PASSED" << endl;
    } else {
        cout << " FAILED" << endl;
        cout << "  Expected: 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969" << endl;
        all_tests_passed = false;
    }
    cout << endl;

    // ============================================================
    // Test 3: File hashing (create test.txt if it doesn't exist)
    // ============================================================
    cout << "[Test 3] SHA-256 of file (test.txt)" << endl;
    
    // Create a test file if it doesn't exist
    const string test_filename = "test.txt";
    ifstream check_file(test_filename);
    if (!check_file.good()) {
        // File doesn't exist, create it with "Hello"
        ofstream create_file(test_filename);
        create_file << "Hello";
        create_file.close();
        cout << "  Created test.txt with content: \"Hello\"" << endl;
    } else {
        check_file.close();
    }

    array<uint8_t, 32> hash_file = sha256_file(test_filename);
    print_hash(hash_file, "  Result");

    // Should match the hash of "Hello" from Test 2
    if (hashes_equal(hash_file, expected_hello)) {
        cout << " PASSED (matches 'Hello' hash)" << endl;
    } else {
        cout << " FAILED (does not match 'Hello' hash)" << endl;
        all_tests_passed = false;
    }
    cout << endl;

    // ============================================================
    // Test 4: Password + salt simulation (database use)
    // ============================================================
    cout << "[Test 4] Password + Salt (simulating database storage)" << endl;
    
    // Simulate registration: user "alice" with password "secret123"
    string salt = "s3cur3s4lt";   // In reality, this would be random bytes
    string password = "secret123";
    string salted_password = salt + password;

    // Hash the salted password (what the server stores)
    array<uint8_t, 32> stored_hash = sha256_data(salted_password);
    print_hash(stored_hash, "  Stored hash (salt + password)");

    // Simulate login: user sends password, server looks up salt and recomputes
    string received_password = "secret123"; // correct
    string received_salted = salt + received_password;
    array<uint8_t, 32> login_hash = sha256_data(received_salted);
    print_hash(login_hash, "  Login hash (from received password)");

    if (hashes_equal(stored_hash, login_hash)) {
        cout << " PASSED (correct password matches)" << endl;
    } else {
        cout << " FAILED (correct password should match)" << endl;
        all_tests_passed = false;
    }

    // Test wrong password
    string wrong_password = "wrongpass";
    string wrong_salted = salt + wrong_password;
    array<uint8_t, 32> wrong_hash = sha256_data(wrong_salted);
    print_hash(wrong_hash, "  Wrong password hash");

    if (!hashes_equal(stored_hash, wrong_hash)) {
        cout << "  PASSED (wrong password does NOT match)" << endl;
    } else {
        cout << "  FAILED (wrong password should NOT match)" << endl;
        all_tests_passed = false;
    }
    cout << endl;

    // ============================================================
    // Summary
    // ============================================================
    cout << "========================================" << endl;
    if (all_tests_passed) {
        cout << "ALL TESTS PASSED! SHA-256 is working correctly." << endl;
    } else {
        cout << "SOME TESTS FAILED. Please check your implementation." << endl;
    }
    cout << "========================================" << endl;

    return all_tests_passed ? EXIT_SUCCESS : EXIT_FAILURE;
}    

