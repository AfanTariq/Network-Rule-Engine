#pragma once
#include <string>
#include <vector>

// EXPLANATION: BasicFileEncryptor Class
// Provides very basic XOR encryption/decryption for file content.

class BasicFileEncryptor {
public:
    // Encrypts a string using XOR with a key.
    static std::string encrypt(const std::string& data, const std::string& key) {
        if (key.empty()) return data; // No encryption if key is empty
        std::string output = data;
        for (size_t i = 0; i < data.length(); ++i) {
            output[i] = data[i] ^ key[i % key.length()];
        }
        return output;
    }

    // Decrypts a string using XOR with a key (XOR is symmetric).
    static std::string decrypt(const std::string& data, const std::string& key) {
        return encrypt(data, key); 
    }
};
