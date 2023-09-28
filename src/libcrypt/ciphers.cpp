#include <libcrypt/utils.hpp>
#include <libcrypt/ciphers.hpp>
#include <fstream>
#include <random>
#include <string>
#include <cstdint>
#include <vector>

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

void shamir_encrypt(
    int64_t mod,
    int64_t recv_rel_prime,
    int64_t send_rel_prime,
    std::ifstream& message_file,
    std::fstream& encrypt_file)
{
    char message_part = 0;

    while (message_file.read(reinterpret_cast<char*>(&message_part), sizeof(message_part)))
    {
        int64_t encrypted_part = libcrypt::pow_mod(
            libcrypt::pow_mod(static_cast<int64_t>(message_part), send_rel_prime, mod), recv_rel_prime, mod);
        encrypt_file.write(reinterpret_cast<const char*>(&encrypted_part), sizeof(int64_t));
    }
}

void shamir_decrypt(
    int64_t mod,
    int64_t recv_inversion,
    int64_t send_inversion,
    std::fstream& encrypt_file,
    std::ofstream& decrypt_file)
{
    int64_t message_part = 0;

    while (encrypt_file.read(reinterpret_cast<char*>(&message_part), sizeof(message_part)))
    {
        decrypt_file << static_cast<char>(
            libcrypt::pow_mod(libcrypt::pow_mod(message_part, send_inversion, mod), recv_inversion, mod));
    }
}

void shamir(
    const std::string& message_filename,
    const std::string& encrypt_filename,
    const std::string& decrypt_filename)
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

}  // namespace libcrypt
