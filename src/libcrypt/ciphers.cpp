#include <libcrypt/utils.hpp>
#include <libcrypt/ciphers.hpp>
#include <fstream>
#include <cstdint>
#include <exception>

namespace libcrypt {

void shamir_encrypt(
    int64_t mod,
    int64_t recv_private_key,
    int64_t send_private_key,
    std::ifstream& message_file,
    std::fstream& encrypt_file)
{
    char message_part = 0;

    while (message_file.read(reinterpret_cast<char*>(&message_part), sizeof(message_part)))
    {
        auto encrypted_part = static_cast<int32_t>(libcrypt::pow_mod(
            libcrypt::pow_mod(static_cast<int64_t>(message_part), send_private_key, mod), recv_private_key, mod));

        encrypt_file.write(reinterpret_cast<const char*>(&encrypted_part), sizeof(encrypted_part));
    }
}

void shamir_decrypt(
    int64_t mod,
    int64_t recv_shared_key,
    int64_t send_shared_key,
    std::fstream& encrypt_file,
    std::ofstream& decrypt_file)
{
    int32_t message_part = 0;

    while (encrypt_file.read(reinterpret_cast<char*>(&message_part), sizeof(message_part)))
    {
        decrypt_file << static_cast<char>(
            libcrypt::pow_mod(libcrypt::pow_mod(message_part, send_shared_key, mod), recv_shared_key, mod));
    }
}

void elgamal_encrypt(
    libcrypt::dh_system_params sys_params,
    int64_t session_key,
    int64_t recv_shared_key,
    std::ifstream& message_file,
    std::fstream& encrypt_file)
{
    char message_part = 0;

    auto ciphertext_first = static_cast<int32_t>(libcrypt::pow_mod(sys_params.base, session_key, sys_params.mod));
    encrypt_file.write(reinterpret_cast<const char*>(&ciphertext_first), sizeof(ciphertext_first));

    while (message_file.read(reinterpret_cast<char*>(&message_part), sizeof(message_part)))
    {
        auto ciphertext_second = static_cast<int32_t>(
            ((static_cast<int64_t>(message_part) % sys_params.mod)
             * (libcrypt::pow_mod(recv_shared_key, session_key, sys_params.mod) % sys_params.mod))
            % sys_params.mod);

        encrypt_file.write(reinterpret_cast<const char*>(&ciphertext_second), sizeof(ciphertext_second));
    }
}

void elgamal_decrypt(int64_t mod, int64_t recv_private_key, std::fstream& encrypt_file, std::ofstream& decrypt_file)
{
    int32_t ciphertext_first = 0;
    int32_t ciphertext_second = 0;

    encrypt_file.read(reinterpret_cast<char*>(&ciphertext_first), sizeof(ciphertext_first));

    while (encrypt_file.read(reinterpret_cast<char*>(&ciphertext_second), sizeof(ciphertext_second)))
    {
        decrypt_file << static_cast<char>(
            ((ciphertext_second % mod) * (libcrypt::pow_mod(ciphertext_first, mod - 1 - recv_private_key, mod) % mod))
            % mod);
    }
}

void vernam_encrypt(std::fstream& vernam_key_file, std::ifstream& message_file, std::fstream& encrypt_file)
{
    char message_part = 0;
    char vernam_key_part = 0;

    while (message_file.read(reinterpret_cast<char*>(&message_part), sizeof(message_part)))
    {
        if (vernam_key_file.read(reinterpret_cast<char*>(&vernam_key_part), sizeof(vernam_key_part)))
        {
            char encrypted_message = static_cast<char>(message_part ^ vernam_key_part);
            encrypt_file.write(reinterpret_cast<const char*>(&encrypted_message), sizeof(char));
        }
        else
        {
            throw std::runtime_error{"Size of vernam key isn't enough to cover the entire message"};
        }
    }
}

void vernam_decrypt(std::fstream& vernam_key_file, std::fstream& encrypt_file, std::ofstream& decrypt_file)
{
    char message_part = 0;
    char vernam_key_part = 0;

    while (encrypt_file.read(reinterpret_cast<char*>(&message_part), sizeof(message_part)))
    {
        if (vernam_key_file.read(reinterpret_cast<char*>(&vernam_key_part), sizeof(vernam_key_part)))
        {
            decrypt_file << static_cast<char>(message_part ^ vernam_key_part);
        }
        else
        {
            throw std::runtime_error{"Size of vernam key isn't enough to cover the entire message"};
        }
    }
}

void rsa_encrypt(int64_t mod, int64_t recv_shared_key, std::ifstream& message_file, std::fstream& encrypt_file)
{
    char message_part = 0;

    while (message_file.read(reinterpret_cast<char*>(&message_part), sizeof(message_part)))
    {
        auto encrypted_part
            = static_cast<int32_t>(libcrypt::pow_mod(static_cast<int64_t>(message_part), recv_shared_key, mod));
        encrypt_file.write(reinterpret_cast<const char*>(&encrypted_part), sizeof(encrypted_part));
    }
}

void rsa_decrypt(int64_t mod, int64_t recv_private_key, std::fstream& encrypt_file, std::ofstream& decrypt_file)
{
    int32_t message_part = 0;

    while (encrypt_file.read(reinterpret_cast<char*>(&message_part), sizeof(message_part)))
    {
        decrypt_file << static_cast<char>(libcrypt::pow_mod(message_part, recv_private_key, mod));
    }
}

}  // namespace libcrypt
