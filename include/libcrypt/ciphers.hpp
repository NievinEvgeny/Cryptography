#pragma once
#include <libcrypt/utils.hpp>
#include <fstream>
#include <cstdint>
#include <string>

namespace libcrypt {

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

void elgamal_encrypt(
    libcrypt::dh_system_params sys_params,
    int64_t session_key,
    int64_t recv_shared_key,
    std::ifstream& message_file,
    std::fstream& encrypt_file);

void elgamal_decrypt(int64_t mod, int64_t recv_private_key, std::fstream& encrypt_file, std::ofstream& decrypt_file);

}  // namespace libcrypt