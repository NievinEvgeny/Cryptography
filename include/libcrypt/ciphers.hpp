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

void shamir_encrypt(
    int64_t mod,
    int64_t recv_rel_prime,
    int64_t send_rel_prime,
    std::ifstream& message_file,
    std::fstream& encrypt_file);

void shamir_decrypt(
    int64_t mod,
    int64_t recv_inversion,
    int64_t send_inversion,
    std::fstream& encrypt_file,
    std::ofstream& decrypt_file);

void shamir(
    const std::string& message_filename,
    const std::string& encrypt_filename,
    const std::string& decrypt_filename);

}  // namespace libcrypt