#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <ctime>
#include <cstring>
#include <openssl/sha.h>
#include <random>
#include <cmath>
#include "../include/totp.h"

// Base32 decoding table
static const char* base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Helper function to decode a Base32 string to binary data
bool base32_decode(const std::string& input, unsigned char* output, size_t& output_length) {
    size_t input_length = input.length();
    if (input_length % 8 != 0) return false;

    for (size_t i = 0; i < input_length; ++i) {
        if (strchr(base32_chars, input[i]) == nullptr) return false;
    }

    output_length = (input_length * 5) / 8;
    memset(output, 0, output_length);

    for (size_t i = 0; i < input_length; ++i) {
        int index = strchr(base32_chars, input[i]) - base32_chars;
        size_t bit_offset = (i % 8) * 5;
        size_t byte_offset = (i / 8) * 5;

        output[byte_offset + (bit_offset / 8)] |= index << (7 - (bit_offset % 8));
        if ((bit_offset % 8) >= 3) {
            output[byte_offset + (bit_offset / 8) + 1] |= index >> (8 - (bit_offset % 8));
        }
    }

    return true;
}

// HMAC-SHA1 implementation
void hmac_sha1(const unsigned char* key, size_t key_len, const unsigned char* message, size_t message_len, unsigned char* hash) {
    unsigned char k_ipad[SHA_DIGEST_LENGTH];
    unsigned char k_opad[SHA_DIGEST_LENGTH];

    memset(k_ipad, 0x36, SHA_DIGEST_LENGTH);
    memset(k_opad, 0x5c, SHA_DIGEST_LENGTH);

    if (key_len > SHA_DIGEST_LENGTH) {
        unsigned char temp_key[SHA_DIGEST_LENGTH];
        SHA_CTX sha_ctx;
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, key, key_len);
        SHA1_Final(temp_key, &sha_ctx);
        memcpy(k_ipad, temp_key, SHA_DIGEST_LENGTH);
        memcpy(k_opad, temp_key, SHA_DIGEST_LENGTH);
    } else {
        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);
    }

    for (size_t i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    unsigned char inner_hash[SHA_DIGEST_LENGTH];
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, k_ipad, SHA_DIGEST_LENGTH);
    SHA1_Update(&sha_ctx, message, message_len);
    SHA1_Final(inner_hash, &sha_ctx);

    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, k_opad, SHA_DIGEST_LENGTH);
    SHA1_Update(&sha_ctx, inner_hash, SHA_DIGEST_LENGTH);
    SHA1_Final(hash, &sha_ctx);
}

// Dynamic truncation
int dynamic_truncation(const unsigned char* hash, int code_digits) {
    int offset = hash[19] & 0xF;
    int bin_code = ((hash[offset] & 0x7F) << 24) |
                   ((hash[offset + 1] & 0xFF) << 16) |
                   ((hash[offset + 2] & 0xFF) << 8) |
                   (hash[offset + 3] & 0xFF);
    return bin_code % static_cast<int>(pow(10, code_digits));
}

// Generate TOTP token
std::string generate_totp(const std::string& secret, int time_step, int code_digits) {
    std::uint64_t current_time = static_cast<std::uint64_t>(std::time(nullptr)) / time_step;
    unsigned char time_buffer[8];
    for (int i = 7; i >= 0; --i) {
        time_buffer[i] = current_time & 0xFF;
        current_time >>= 8;
    }

    unsigned char decoded_secret[32];
    size_t secret_length;
    if (!base32_decode(secret, decoded_secret, secret_length)) {
        throw std::invalid_argument("Invalid Base32 encoded secret");
    }

    unsigned char hash[SHA_DIGEST_LENGTH];
    hmac_sha1(decoded_secret, secret_length, time_buffer, sizeof(time_buffer), hash);

    int otp = dynamic_truncation(hash, code_digits);

    std::ostringstream oss;
    oss << std::setw(code_digits) << std::setfill('0') << otp;
    return oss.str();
}

// Verify TOTP token
bool verify_totp(const std::string& token, const std::string& secret, int time_step, int code_digits, int window) {
    try {
        int otp = std::stoi(token);
        std::uint64_t current_time = static_cast<std::uint64_t>(std::time(nullptr)) / time_step;

        for (int i = -window; i <= window; ++i) {
            std::uint64_t counter = current_time + i;
            unsigned char time_buffer[8];
            for (int j = 7; j >= 0; --j) {
                time_buffer[j] = counter & 0xFF;
                counter >>= 8;
            }

            unsigned char decoded_secret[32];
            size_t secret_length;
            if (!base32_decode(secret, decoded_secret, secret_length)) {
                throw std::invalid_argument("Invalid Base32 encoded secret");
            }

            unsigned char hash[SHA_DIGEST_LENGTH];
            hmac_sha1(decoded_secret, secret_length, time_buffer, sizeof(time_buffer), hash);

            int generated_otp = dynamic_truncation(hash, code_digits);
            if (generated_otp == otp) {
                return true;
            }
        }
    } catch (...) {
        return false;
    }
    return false;
}

// Generate random Base32 secret
std::string generate_random_base32_secret(size_t length) {
    std::string secret;
    std::mt19937 rng(static_cast<unsigned int>(std::time(nullptr)));
    std::uniform_int_distribution<> dist(0, 31);

    for (size_t i = 0; i < length; ++i) {
        secret += base32_chars[dist(rng)];
    }

    return secret;
}