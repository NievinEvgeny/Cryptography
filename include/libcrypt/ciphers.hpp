#pragma once
#include <libcrypt/utils.hpp>
#include <fstream>
#include <cstdint>
#include <string>

namespace libcrypt {

void shamir_encrypt(
    int64_t mod,
    int64_t recv_private_key,
    int64_t send_private_key,
    std::ifstream& message_file,
    std::fstream& encrypt_file);

void shamir_decrypt(
    int64_t mod,
    int64_t recv_shared_key,
    int64_t send_shared_key,
    std::fstream& encrypt_file,
    std::ofstream& decrypt_file);

void elgamal_encrypt(
    libcrypt::dh_system_params sys_params,
    int64_t session_key,
    int64_t recv_shared_key,
    std::ifstream& message_file,
    std::fstream& encrypt_file);

void elgamal_decrypt(int64_t mod, int64_t recv_private_key, std::fstream& encrypt_file, std::ofstream& decrypt_file);

void vernam_encrypt(std::fstream& vernam_key_file, std::ifstream& message_file, std::fstream& encrypt_file);

void vernam_decrypt(std::fstream& vernam_key_file, std::fstream& encrypt_file, std::ofstream& decrypt_file);

void rsa_encrypt(int64_t mod, int64_t recv_shared_key, std::ifstream& message_file, std::fstream& encrypt_file);

void rsa_decrypt(int64_t mod, int64_t recv_private_key, std::fstream& encrypt_file, std::ofstream& decrypt_file);

}  // namespace libcrypt