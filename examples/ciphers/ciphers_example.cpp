#include "ciphers_example.hpp"
#include <libcrypt/utils.hpp>
#include <fstream>
#include <cstdint>
#include <random>
#include <vector>
#include <filesystem>

namespace libcrypt {

static libcrypt::shamir_user_params shamir_gen_user_params(int64_t mod)
{
    int64_t relative_prime = 0;
    std::vector<int64_t> gcd_result;

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> rel_prime_range(INT16_MAX, mod - 1);

    do
    {
        relative_prime = rel_prime_range(mt);
        gcd_result = libcrypt::extended_gcd(mod - 1, relative_prime);
    } while (gcd_result.front() != 1);

    int64_t inversion = gcd_result.back();

    if (inversion < 0)
    {
        inversion += mod - 1;
    }

    return {relative_prime, inversion};
}

void cipher_call_example(const cxxopts::ParseResult& parse_cmd_line)
{
    const std::filesystem::path message_path = parse_cmd_line["message"].as<std::string>();
    const std::filesystem::path encrypt_path = parse_cmd_line["encrypt"].as<std::string>();
    const std::filesystem::path decrypt_path = parse_cmd_line["decrypt"].as<std::string>();

    std::ifstream message_file(message_path, std::ios::binary);
    if (!message_file.is_open())
    {
        throw std::runtime_error{'"' + message_path.string() + '"' + " not found"};
    }

    std::fstream encryption_file(encrypt_path, std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);
    if (!encryption_file.is_open())
    {
        throw std::runtime_error{'"' + encrypt_path.string() + '"' + " not found"};
    }

    std::ofstream decryption_file(decrypt_path, std::ios::binary);
    if (!decryption_file.is_open())
    {
        throw std::runtime_error{'"' + decrypt_path.string() + '"' + " not found"};
    }

    if (parse_cmd_line.count("shamir"))
    {
        int64_t mod = 0;
        std::random_device rd;
        std::mt19937 mt(rd());
        std::uniform_int_distribution<int64_t> mod_range(INT16_MAX, INT32_MAX);

        do
        {
            mod = mod_range(mt);
        } while (!libcrypt::is_prime(mod));

        const libcrypt::shamir_user_params sender_params = shamir_gen_user_params(mod);
        const libcrypt::shamir_user_params reciever_params = shamir_gen_user_params(mod);

        libcrypt::shamir_encrypt(
            mod, reciever_params.relative_prime, sender_params.relative_prime, message_file, encryption_file);

        encryption_file.seekp(0, std::ios::beg);

        libcrypt::shamir_decrypt(
            mod, reciever_params.inversion, sender_params.inversion, encryption_file, decryption_file);
    }

    if (parse_cmd_line.count("elgamal"))
    {
        libcrypt::dh_system_params sys_params = libcrypt::gen_dh_system();

        std::random_device rd;
        std::mt19937 mt(rd());
        std::uniform_int_distribution<int64_t> private_key_range(2, sys_params.mod - 2);
        std::uniform_int_distribution<int64_t> session_key_range(1, sys_params.mod - 2);

        int64_t recv_private_key = private_key_range(mt);
        int64_t recv_shared_key = libcrypt::pow_mod(sys_params.base, recv_private_key, sys_params.mod);
        int64_t session_key = session_key_range(mt);

        libcrypt::elgamal_encrypt(sys_params, session_key, recv_shared_key, message_file, encryption_file);

        encryption_file.seekp(0, std::ios::beg);

        libcrypt::elgamal_decrypt(sys_params.mod, recv_private_key, encryption_file, decryption_file);
    }

    if (parse_cmd_line.count("vernam"))
    {
        const std::filesystem::path vernam_key_path = parse_cmd_line["vernam_key"].as<std::string>();

        std::random_device rd;
        std::mt19937 mt(rd());
        std::uniform_int_distribution<int16_t> randomizer(CHAR_MIN, CHAR_MAX);

        std::fstream vernam_key_file(
            vernam_key_path, std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);
        if (!vernam_key_file.is_open())
        {
            throw std::runtime_error{'"' + vernam_key_path.string() + '"' + " not found"};
        }

        for (uintmax_t i = 0; i < std::filesystem::file_size(message_path); i++)
        {
            char rand = static_cast<char>(randomizer(mt));
            vernam_key_file.write(reinterpret_cast<const char*>(&rand), sizeof(char));
        }

        vernam_key_file.seekp(0, std::ios::beg);

        libcrypt::vernam_encrypt(vernam_key_file, message_file, encryption_file);

        encryption_file.seekp(0, std::ios::beg);
        vernam_key_file.seekp(0, std::ios::beg);

        libcrypt::vernam_decrypt(vernam_key_file, encryption_file, decryption_file);

        vernam_key_file.close();
    }

    if (parse_cmd_line.count("rsa"))
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
            } while (!libcrypt::is_prime(mod_part_Q));

            euler_func_res = (mod_part_P - 1) * (mod_part_Q - 1);
            gcd_result = libcrypt::extended_gcd(recv_shared_key, euler_func_res);
        } while (gcd_result.front() != 1);

        int64_t mod = mod_part_P * mod_part_Q;
        int64_t recv_private_key = gcd_result.back();

        if (recv_private_key < 0)
        {
            recv_private_key += euler_func_res;
        }

        libcrypt::rsa_encrypt(mod, recv_shared_key, message_file, encryption_file);

        encryption_file.seekp(0, std::ios::beg);

        libcrypt::rsa_decrypt(mod, recv_private_key, encryption_file, decryption_file);
    }

    message_file.close();
    encryption_file.close();
    decryption_file.close();
}

}  // namespace libcrypt