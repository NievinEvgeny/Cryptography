#include <libcrypt/signatures.hpp>
#include <libcrypt/utils.hpp>
#include <PicoSHA2/picosha2.h>
#include <string>
#include <iterator>
#include <fstream>
#include <vector>
#include <cstdint>
#include <limits>
#include <cstdio>
#include <random>

namespace libcrypt {

constexpr int64_t file_hash_size = 64 * sizeof(int32_t);

static std::string calc_file_hash(std::fstream& file)
{
    std::vector<unsigned char> bin_file_hash(picosha2::k_digest_size);
    picosha2::hash256(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>(),
        bin_file_hash.begin(),
        bin_file_hash.end());
    return picosha2::bytes_to_hex_string(bin_file_hash.begin(), bin_file_hash.end());
}

void rsa_file_signing(int64_t mod, int64_t send_private_key, std::fstream& file)
{
    const std::string file_hash{libcrypt::calc_file_hash(file)};

    for (const char& hash_part : file_hash)
    {
        const auto signed_hash_part
            = static_cast<int32_t>(libcrypt::pow_mod(static_cast<int64_t>(hash_part), send_private_key, mod));
        file.write(reinterpret_cast<const char*>(&signed_hash_part), sizeof(signed_hash_part));
    }
}

bool rsa_check_file_sign(int64_t mod, int64_t send_shared_key, std::fstream& file)
{
    file.seekg(-1 * file_hash_size, std::ios::end);
    const int64_t data_size = file.tellg();
    file.seekg(std::ios::beg);

    std::fstream file_data("tmp.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::app);

    if (!file_data.is_open())
    {
        throw std::runtime_error{"can't create tmp buf file in rsa sign\n"};
    }

    std::copy_n(std::istreambuf_iterator<char>(file), data_size, std::ostreambuf_iterator<char>(file_data));

    file_data.seekg(std::ios::beg);

    const std::string file_hash{libcrypt::calc_file_hash(file_data)};

    file.seekg(-1 * file_hash_size, std::ios::end);

    for (const auto& hash_part : file_hash)
    {
        int32_t signed_hash_part = 0;
        file.read(reinterpret_cast<char*>(&signed_hash_part), sizeof(signed_hash_part));

        if (hash_part != libcrypt::pow_mod(static_cast<int64_t>(signed_hash_part), send_shared_key, mod))
        {
            static_cast<void>(std::remove("tmp.txt"));
            return false;
        }
    }
    static_cast<void>(std::remove("tmp.txt"));
    return true;
}

void elgamal_file_signing(
    libcrypt::dh_system_params sys_params,
    int64_t session_key,
    int64_t recv_private_key,
    std::fstream& file)
{
    const std::string file_hash{libcrypt::calc_file_hash(file)};

    const auto sign_first = static_cast<int32_t>(libcrypt::pow_mod(sys_params.base, session_key, sys_params.mod));
    file.write(reinterpret_cast<const char*>(&sign_first), sizeof(sign_first));

    const int64_t inv_session_key = libcrypt::extended_gcd(sys_params.mod - 1, session_key).back();

    for (const auto& hash_part : file_hash)
    {
        const auto signed_hash_part = static_cast<int32_t>(libcrypt::mod(
            inv_session_key
                * (libcrypt::mod(static_cast<int64_t>(hash_part) - recv_private_key * sign_first, sys_params.mod - 1)),
            sys_params.mod - 1));

        file.write(reinterpret_cast<const char*>(&signed_hash_part), sizeof(signed_hash_part));
    }
}

bool elgamal_check_file_sign(libcrypt::dh_system_params sys_params, int64_t recv_shared_key, std::fstream& file)
{
    constexpr int64_t sign_size = file_hash_size + sizeof(int32_t);

    file.seekg(-1 * sign_size, std::ios::end);
    const int64_t data_size = file.tellg();
    file.seekg(std::ios::beg);

    std::fstream file_data("tmp.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::app);

    if (!file_data.is_open())
    {
        throw std::runtime_error{"can't create tmp buf file in elgamal sign\n"};
    }

    std::copy_n(std::istreambuf_iterator<char>(file), data_size, std::ostreambuf_iterator<char>(file_data));

    file_data.seekg(std::ios::beg);

    const std::string file_hash{libcrypt::calc_file_hash(file_data)};

    file.seekg(-1 * sign_size, std::ios::end);

    int32_t sign_first = 0;
    file.read(reinterpret_cast<char*>(&sign_first), sizeof(sign_first));

    for (const auto& hash_part : file_hash)
    {
        int32_t signed_hash_part = 0;
        file.read(reinterpret_cast<char*>(&signed_hash_part), sizeof(signed_hash_part));

        if (libcrypt::pow_mod(sys_params.base, static_cast<int64_t>(hash_part), sys_params.mod)
            != libcrypt::mod(
                libcrypt::pow_mod(recv_shared_key, sign_first, sys_params.mod)
                    * libcrypt::pow_mod(sign_first, static_cast<int64_t>(signed_hash_part), sys_params.mod),
                sys_params.mod))
        {
            static_cast<void>(std::remove("tmp.txt"));
            return false;
        }
    }
    static_cast<void>(std::remove("tmp.txt"));
    return true;
}

static bool gost_hash_to_sign(
    const std::string& file_hash,
    int8_t sign_length,
    int64_t rand_num,
    int64_t send_private_key,
    int64_t elliptic_exp,
    std::vector<int32_t>& signature)
{
    for (char i = 1; i < sign_length; i++)
    {
        signature.emplace_back(static_cast<int32_t>(
            libcrypt::mod(rand_num * file_hash.at(i - 1) + send_private_key * signature.at(0), elliptic_exp)));

        if (signature[i] == 0)
        {
            return false;
        }
    }

    return true;
}

void gost_file_signing(
    int64_t mod,
    int64_t elliptic_exp,
    int64_t elliptic_coef,
    int64_t send_private_key,
    std::fstream& file)
{
    constexpr int16_t sign_size = file_hash_size + sizeof(int32_t);
    constexpr int8_t sign_length = sign_size / sizeof(int32_t);

    const std::string file_hash{libcrypt::calc_file_hash(file)};

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> rand_num_gen_range(1, elliptic_exp - 1);

    while (true)
    {
        int64_t rand_num = rand_num_gen_range(mt);
        std::vector<int32_t> signature;
        signature.reserve(sign_length);

        signature.emplace_back(
            static_cast<int32_t>(libcrypt::mod(libcrypt::pow_mod(elliptic_coef, rand_num, mod), elliptic_exp)));

        if (signature[0] == 0)
        {
            continue;
        }

        if (!libcrypt::gost_hash_to_sign(file_hash, sign_length, rand_num, send_private_key, elliptic_exp, signature))
        {
            continue;
        }

        file.write(reinterpret_cast<char*>(signature.data()), sign_size);

        return;
    }
}

bool gost_check_file_sign(
    int64_t mod,
    int64_t elliptic_exp,
    int64_t elliptic_coef,
    int64_t send_shared_key,
    std::fstream& file)
{
    constexpr int64_t sign_size = file_hash_size + sizeof(int32_t);

    file.seekg(-1 * sign_size, std::ios::end);
    const int64_t data_size = file.tellg();
    file.seekg(std::ios::beg);

    std::fstream file_data("tmp.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::app);

    if (!file_data.is_open())
    {
        throw std::runtime_error{"can't create tmp buf file in gost sign\n"};
    }

    std::copy_n(std::istreambuf_iterator<char>(file), data_size, std::ostreambuf_iterator<char>(file_data));

    file_data.seekg(std::ios::beg);

    const std::string file_hash{libcrypt::calc_file_hash(file_data)};

    file.seekg(-1 * sign_size, std::ios::end);

    int32_t sign_first = 0;
    file.read(reinterpret_cast<char*>(&sign_first), sizeof(int32_t));

    if ((sign_first <= 0) || (sign_first >= elliptic_exp))
    {
        return false;
    }

    for (const auto& hash_part : file_hash)
    {
        int32_t signed_hash_part = 0;
        file.read(reinterpret_cast<char*>(&signed_hash_part), sizeof(signed_hash_part));

        if ((signed_hash_part <= 0) || (signed_hash_part >= elliptic_exp))
        {
            return false;
        }

        const int64_t inversion = libcrypt::extended_gcd(hash_part, elliptic_exp).back();

        if (sign_first
            != libcrypt::mod(
                libcrypt::mod(
                    libcrypt::pow_mod(elliptic_coef, libcrypt::mod(signed_hash_part * inversion, elliptic_exp), mod)
                        * libcrypt::pow_mod(
                            send_shared_key,
                            libcrypt::mod(-1 * static_cast<int64_t>(sign_first) * inversion, elliptic_exp),
                            mod),
                    mod),
                elliptic_exp))
        {
            static_cast<void>(std::remove("tmp.txt"));
            return false;
        }
    }
    static_cast<void>(std::remove("tmp.txt"));
    return true;
}

}  // namespace libcrypt