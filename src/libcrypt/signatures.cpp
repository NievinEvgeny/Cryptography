#include <libcrypt/signatures.hpp>
#include <libcrypt/utils.hpp>
#include <PicoSHA2/picosha2.h>
#include <string>
#include <iterator>
#include <fstream>
#include <vector>
#include <cstdint>

namespace libcrypt {

constexpr int64_t file_hash_size = 64 * sizeof(int64_t);

static std::string calc_str_hash(const std::string& str)
{
    return picosha2::hash256_hex_string(str);
}

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
        int64_t encrypted_hash_part = libcrypt::pow_mod(static_cast<int64_t>(hash_part), send_private_key, mod);
        file.write(reinterpret_cast<const char*>(&encrypted_hash_part), sizeof(int64_t));
    }
}

bool rsa_check_file_sign(int64_t mod, int64_t send_shared_key, std::fstream& file)
{
    std::string file_data{(std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>()};
    file_data.erase(file_data.end() - file_hash_size, file_data.end());
    std::string file_hash{libcrypt::calc_str_hash(file_data)};

    file.seekg(-1 * file_hash_size, std::ios::end);

    for (const auto& hash_part : file_hash)
    {
        int64_t encrypted_hash_part = 0;
        file.read(reinterpret_cast<char*>(&encrypted_hash_part), sizeof(int64_t));

        if (hash_part != libcrypt::pow_mod(encrypted_hash_part, send_shared_key, mod))
        {
            return false;
        }
    }
    return true;
}

}  // namespace libcrypt