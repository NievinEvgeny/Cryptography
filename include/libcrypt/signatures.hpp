#pragma once
#include <libcrypt/utils.hpp>
#include <fstream>

namespace libcrypt {

void rsa_file_signing(int64_t mod, int64_t send_private_key, std::fstream& file);

bool rsa_check_file_sign(int64_t mod, int64_t send_shared_key, std::fstream& file);

void elgamal_file_signing(
    libcrypt::dh_system_params sys_params,
    int64_t session_key,
    int64_t recv_private_key,
    std::fstream& file);

bool elgamal_check_file_sign(libcrypt::dh_system_params sys_params, int64_t recv_shared_key, std::fstream& file);

void gost_file_signing(
    int64_t mod,
    int64_t elliptic_exp,
    int64_t elliptic_coef,
    int64_t send_private_key,
    std::fstream& file);

bool gost_check_file_sign(
    int64_t mod,
    int64_t elliptic_exp,
    int64_t elliptic_coef,
    int64_t send_shared_key,
    std::fstream& file);

}  // namespace libcrypt