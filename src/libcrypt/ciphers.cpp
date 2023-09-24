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

void shamir_encrypt(std::ifstream& message_file, int64_t relative_prime, int64_t mod)
{
    char message_part = 0;

    std::ofstream encryption_file("encryption.txt", std::ios::binary);

    if (!encryption_file.is_open())
    {
        throw std::runtime_error{"Can't open file in shamir encryption"};
    }

    while (message_file.read(reinterpret_cast<char*>(&message_part), sizeof(message_part)))
    {
        int64_t temp = libcrypt::pow_mod(static_cast<int64_t>(message_part), relative_prime, mod);
        encryption_file.write(reinterpret_cast<const char*>(&temp), sizeof(int64_t));
    }
}

void shamir_decrypt(libcrypt::shamir_user_params user1, libcrypt::shamir_user_params user2, int64_t mod)
{
    std::ifstream encrypted_file("encryption.txt", std::ios::binary);

    if (!encrypted_file.is_open())
    {
        throw std::runtime_error{"Can't open file in shamir decryption"};
    }

    std::ofstream decryption_file("decryption.txt", std::ios::binary);

    if (!decryption_file.is_open())
    {
        throw std::runtime_error{"Can't open file in shamir decryption"};
    }

    int64_t message_part = 0;

    while (encrypted_file.read(reinterpret_cast<char*>(&message_part), sizeof(message_part)))
    {
        int64_t step2 = libcrypt::pow_mod(message_part, user2.relative_prime, mod);
        int64_t step3 = libcrypt::pow_mod(step2, user1.inversion, mod);
        decryption_file << static_cast<char>(libcrypt::pow_mod(step3, user2.inversion, mod));
    }
}

void shamir(const std::string& message_filename)
{
    std::ifstream message_file(message_filename, std::ios::binary);

    if (!message_file.is_open())
    {
        throw std::runtime_error{'"' + message_filename + '"' + " not found"};
    }

    int64_t mod = 0;
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> mod_range(INT16_MAX, INT32_MAX);

    do
    {
        mod = mod_range(mt);
    } while (!libcrypt::is_prime(mod));

    libcrypt::shamir_user_params user1 = shamir_gen_user_params(mod);
    libcrypt::shamir_user_params user2 = shamir_gen_user_params(mod);

    shamir_encrypt(message_file, user1.relative_prime, mod);
    shamir_decrypt(user1, user2, mod);
}

}  // namespace libcrypt
