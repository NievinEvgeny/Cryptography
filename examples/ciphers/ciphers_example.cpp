#include <ciphers/ciphers_example.hpp>
#include <params/gen_params.hpp>
#include <libcrypt/ciphers.hpp>
#include <libcrypt/utils.hpp>
#include <fstream>
#include <climits>
#include <random>
#include <filesystem>

namespace libcrypt {

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
        libcrypt::shamir_sys_params params = libcrypt::shamir_gen_sys();

        libcrypt::shamir_encrypt(
            params.mod, params.recv.private_key, params.send.private_key, message_file, encryption_file);

        encryption_file.seekp(0, std::ios::beg);

        libcrypt::shamir_decrypt(
            params.mod, params.recv.shared_key, params.send.shared_key, encryption_file, decryption_file);
    }

    if (parse_cmd_line.count("elgamal"))
    {
        libcrypt::elgamal_sys_params params = libcrypt::elgamal_gen_sys();

        libcrypt::elgamal_encrypt(
            params.dh_sys_params, params.session_key, params.recv.shared_key, message_file, encryption_file);

        encryption_file.seekp(0, std::ios::beg);

        libcrypt::elgamal_decrypt(params.dh_sys_params.mod, params.recv.private_key, encryption_file, decryption_file);
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
        libcrypt::rsa_sys_params params = libcrypt::rsa_gen_sys();

        libcrypt::rsa_encrypt(params.mod, params.recv.shared_key, message_file, encryption_file);

        encryption_file.seekp(0, std::ios::beg);

        libcrypt::rsa_decrypt(params.mod, params.recv.private_key, encryption_file, decryption_file);
    }

    message_file.close();
    encryption_file.close();
    decryption_file.close();
}

}  // namespace libcrypt