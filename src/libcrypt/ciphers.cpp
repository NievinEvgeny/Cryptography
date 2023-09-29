#include <libcrypt/utils.hpp>
#include <libcrypt/ciphers.hpp>
#include <fstream>
#include <cstdint>

namespace libcrypt {

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

}  // namespace libcrypt
