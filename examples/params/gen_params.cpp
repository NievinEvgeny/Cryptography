#include <params/gen_params.hpp>
#include <libcrypt/utils.hpp>
#include <random>
#include <vector>
#include <cstdint>

namespace libcrypt {

static libcrypt::crypt_user_params shamir_gen_user_params(int64_t mod)
{
    int64_t private_key = 0;
    std::vector<int64_t> gcd_result;

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> private_key_range(INT16_MAX, mod - 1);

    do
    {
        private_key = private_key_range(mt);
        gcd_result = libcrypt::extended_gcd(mod - 1, private_key);
    } while (gcd_result.front() != 1);

    int64_t shared_key = gcd_result.back();

    if (shared_key < 0)
    {
        shared_key += mod - 1;
    }

    return {private_key, shared_key};
}

libcrypt::shamir_sys_params shamir_gen_sys()
{
    int64_t mod = 0;
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> mod_range(INT16_MAX, INT32_MAX);

    do
    {
        mod = mod_range(mt);
    } while (!libcrypt::is_prime(mod));

    const libcrypt::crypt_user_params sender_params = libcrypt::shamir_gen_user_params(mod);
    const libcrypt::crypt_user_params reciever_params = libcrypt::shamir_gen_user_params(mod);

    return {sender_params, reciever_params, mod};
}

libcrypt::elgamal_sys_params elgamal_gen_sys()
{
    libcrypt::dh_system_params dh_sys_params = libcrypt::gen_dh_system();

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> private_key_range(2, dh_sys_params.mod - 2);
    std::uniform_int_distribution<int64_t> session_key_range(1, dh_sys_params.mod - 2);

    int64_t session_key = 0;
    int64_t recv_private_key = private_key_range(mt);
    int64_t recv_shared_key = libcrypt::pow_mod(dh_sys_params.base, recv_private_key, dh_sys_params.mod);

    do
    {
        session_key = session_key_range(mt);
    } while (libcrypt::extended_gcd(session_key, dh_sys_params.mod - 1).front() != 1);

    return {dh_sys_params, {recv_private_key, recv_shared_key}, session_key};
}

libcrypt::rsa_sys_params rsa_gen_sys()
{
    constexpr int64_t recv_shared_key = 3;
    std::vector<int64_t> gcd_result;

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> prime_gen_range(UINT8_MAX, INT16_MAX);

    int64_t mod_part_P = 0;
    int64_t mod_part_Q = 0;
    int64_t euler_func_res = 0;

    do
    {
        do
        {
            mod_part_P = prime_gen_range(mt);
        } while (!libcrypt::is_prime(mod_part_P));

        do
        {
            mod_part_Q = prime_gen_range(mt);
        } while (!libcrypt::is_prime(mod_part_Q) || (mod_part_Q == mod_part_P));

        euler_func_res = (mod_part_P - 1) * (mod_part_Q - 1);
        gcd_result = libcrypt::extended_gcd(recv_shared_key, euler_func_res);
    } while (gcd_result.front() != 1);

    int64_t mod = mod_part_P * mod_part_Q;
    int64_t recv_private_key = gcd_result.back();

    if (recv_private_key < 0)
    {
        recv_private_key += euler_func_res;
    }

    return {{recv_private_key, recv_shared_key}, mod};
}

libcrypt::gost_sys_params gost_gen_sys()
{
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> elliptic_exp_gen_range(UINT16_MAX / 2 + 1, UINT16_MAX);

    int64_t elliptic_exp = 0;

    do
    {
        elliptic_exp = elliptic_exp_gen_range(mt);
    } while (!libcrypt::is_prime(elliptic_exp));

    std::uniform_int_distribution<int64_t> tmp_elliptic_coef_gen_range(INT16_MAX, INT32_MAX / elliptic_exp - 1);

    int64_t tmp_elliptic_coef = 0;
    int64_t mod = 0;

    do
    {
        tmp_elliptic_coef = tmp_elliptic_coef_gen_range(mt);
        mod = tmp_elliptic_coef * elliptic_exp + 1;
    } while (!libcrypt::is_prime(mod));

    std::uniform_int_distribution<int64_t> tmp_base_gen_range(1, mod - 1);

    int64_t tmp_base = 0;
    int64_t elliptic_coef = 0;

    do
    {
        tmp_base = tmp_base_gen_range(mt);
        elliptic_coef = libcrypt::pow_mod(tmp_base, tmp_elliptic_coef, mod);
    } while (elliptic_coef <= 1);

    std::uniform_int_distribution<int64_t> private_key_gen_range(1, elliptic_exp - 1);

    int64_t send_private_key = private_key_gen_range(mt);
    int64_t send_shared_key = libcrypt::pow_mod(elliptic_coef, send_private_key, mod);

    return {{send_private_key, send_shared_key}, elliptic_exp, elliptic_coef, mod};
}

}  // namespace libcrypt