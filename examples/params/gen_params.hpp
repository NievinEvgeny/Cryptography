#pragma once
#include <libcrypt/utils.hpp>
#include <cstdint>

namespace libcrypt {

struct crypt_user_params
{
    int64_t private_key;
    int64_t shared_key;
};

struct shamir_sys_params
{
    libcrypt::crypt_user_params recv;
    libcrypt::crypt_user_params send;
    int64_t mod;
};

struct elgamal_sys_params
{
    libcrypt::dh_system_params dh_sys_params;
    libcrypt::crypt_user_params recv;
    int64_t session_key;
};

struct rsa_sys_params
{
    libcrypt::crypt_user_params recv;
    int64_t mod;
};

libcrypt::crypt_user_params shamir_gen_user_params(int64_t mod);

libcrypt::shamir_sys_params shamir_gen_sys();

libcrypt::elgamal_sys_params elgamal_gen_sys();

libcrypt::rsa_sys_params rsa_gen_sys();

}  // namespace libcrypt