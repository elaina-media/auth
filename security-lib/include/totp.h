#pragma once

#include <string>

// Function prototypes
std::string generate_random_base32_secret(size_t length);
std::string generate_totp(const std::string& secret, int time_step = 30, int code_digits = 6);
bool verify_totp(const std::string& token, const std::string& secret, int time_step = 30, int code_digits = 6, int window = 1);