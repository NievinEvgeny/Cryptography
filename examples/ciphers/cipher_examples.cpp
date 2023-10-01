#include "cipher_examples.hpp"
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
    std::uniform_int_distribution<int64_t> num_range(INT16_MAX, INT32_MAX);

    do
    {
        relative_prime = num_range(mt);
        gcd_result = libcrypt::extended_gcd(mod - 1, relative_prime);
    } while ((gcd_result.front() != 1) || (gcd_result.back() >= mod) || (relative_prime >= mod));

    int64_t inversion = gcd_result.back();

    if (inversion < 0)
    {
        inversion += mod - 1;
    }

    return {relative_prime, inversion};
}

void shamir_example(const cxxopts::ParseResult& parse_cmd_line)
{
    const std::string message_filename = parse_cmd_line["message"].as<std::string>();
    const std::string encrypt_filename = parse_cmd_line["encrypt"].as<std::string>();
    const std::string decrypt_filename = parse_cmd_line["decrypt"].as<std::string>();

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

    std::ifstream message_file(message_filename, std::ios::binary);
    if (!message_file.is_open())
    {
        throw std::runtime_error{'"' + message_filename + '"' + " not found"};
    }

    std::fstream encryption_file(encrypt_filename, std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);
    if (!encryption_file.is_open())
    {
        throw std::runtime_error{'"' + encrypt_filename + '"' + " not found"};
    }

    shamir_encrypt(mod, reciever_params.relative_prime, sender_params.relative_prime, message_file, encryption_file);

    message_file.close();
    encryption_file.seekp(0, std::ios::beg);

    std::ofstream decryption_file(decrypt_filename, std::ios::binary);
    if (!decryption_file.is_open())
    {
        throw std::runtime_error{'"' + decrypt_filename + '"' + " not found"};
    }

    shamir_decrypt(mod, reciever_params.inversion, sender_params.inversion, encryption_file, decryption_file);

    encryption_file.close();
    decryption_file.close();
}

void elgamal_example(const cxxopts::ParseResult& parse_cmd_line)
{
    const std::string message_filename = parse_cmd_line["message"].as<std::string>();
    const std::string encrypt_filename = parse_cmd_line["encrypt"].as<std::string>();
    const std::string decrypt_filename = parse_cmd_line["decrypt"].as<std::string>();

    libcrypt::dh_system_params sys_params = libcrypt::gen_dh_system();

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> private_key_range(2, sys_params.mod - 2);
    std::uniform_int_distribution<int64_t> session_key_range(1, sys_params.mod - 2);

    int64_t recv_private_key = private_key_range(mt);
    int64_t recv_shared_key = libcrypt::pow_mod(sys_params.base, recv_private_key, sys_params.mod);
    int64_t session_key = 0;

    do
    {
        session_key = session_key_range(mt);
    } while (libcrypt::extended_gcd(sys_params.mod - 1, session_key).front() != 1);

    std::ifstream message_file(message_filename, std::ios::binary);
    if (!message_file.is_open())
    {
        throw std::runtime_error{'"' + message_filename + '"' + " not found"};
    }

    std::fstream encryption_file(encrypt_filename, std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);
    if (!encryption_file.is_open())
    {
        throw std::runtime_error{'"' + encrypt_filename + '"' + " not found"};
    }

    libcrypt::elgamal_encrypt(sys_params, session_key, recv_shared_key, message_file, encryption_file);

    message_file.close();
    encryption_file.seekp(0, std::ios::beg);

    std::ofstream decryption_file(decrypt_filename, std::ios::binary);
    if (!decryption_file.is_open())
    {
        throw std::runtime_error{'"' + decrypt_filename + '"' + " not found"};
    }

    libcrypt::elgamal_decrypt(sys_params.mod, recv_private_key, encryption_file, decryption_file);

    encryption_file.close();
    decryption_file.close();
}

void vernam_example(const cxxopts::ParseResult& parse_cmd_line)
{
    const std::filesystem::path message_path = parse_cmd_line["message"].as<std::string>();
    const std::string encrypt_filename = parse_cmd_line["encrypt"].as<std::string>();
    const std::string decrypt_filename = parse_cmd_line["decrypt"].as<std::string>();
    const std::string vernam_key_filename = parse_cmd_line["vernam_key"].as<std::string>();

    std::ifstream message_file(message_path, std::ios::binary);
    if (!message_file.is_open())
    {
        throw std::runtime_error{'"' + message_path.string() + '"' + " not found"};
    }

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int16_t> randomizer(CHAR_MIN, CHAR_MAX);

    std::fstream vernam_key_file(
        vernam_key_filename, std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);
    if (!vernam_key_file.is_open())
    {
        throw std::runtime_error{'"' + vernam_key_filename + '"' + " not found"};
    }

    for (uintmax_t i = 0; i < std::filesystem::file_size(message_path); i++)
    {
        char rand = static_cast<char>(randomizer(mt));
        vernam_key_file.write(reinterpret_cast<const char*>(&rand), sizeof(char));
    }

    vernam_key_file.seekp(0, std::ios::beg);

    std::fstream encryption_file(encrypt_filename, std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);
    if (!encryption_file.is_open())
    {
        throw std::runtime_error{'"' + encrypt_filename + '"' + " not found"};
    }

    libcrypt::vernam_encrypt(vernam_key_file, message_file, encryption_file);

    message_file.close();
    encryption_file.seekp(0, std::ios::beg);
    vernam_key_file.seekp(0, std::ios::beg);

    std::ofstream decryption_file(decrypt_filename, std::ios::binary);
    if (!decryption_file.is_open())
    {
        throw std::runtime_error{'"' + decrypt_filename + '"' + " not found"};
    }

    libcrypt::vernam_decrypt(vernam_key_file, encryption_file, decryption_file);

    encryption_file.close();
    decryption_file.close();
    vernam_key_file.close();
}

}  // namespace libcrypt