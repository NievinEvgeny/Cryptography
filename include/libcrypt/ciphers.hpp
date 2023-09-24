#pragma once
#include <fstream>
#include <cstdint>
#include <string>

namespace libcrypt {

struct shamir_user_params
{
    int64_t relative_prime;
    int64_t inversion;
};

void shamir_encrypt(std::ifstream& message_file, int64_t secret_relative_prime, int64_t mod);

void shamir_decrypt(libcrypt::shamir_user_params user1, libcrypt::shamir_user_params user2, int64_t mod);

void shamir(const std::string& message_filename);

}  // namespace libcrypt