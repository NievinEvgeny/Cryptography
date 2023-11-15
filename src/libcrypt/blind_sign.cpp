#include <libcrypt/blind_sign.hpp>
#include <libcrypt/utils.hpp>
#include <PicoSHA2/picosha2.h>
#include <random>
#include <string>
#include <fstream>
#include <exception>
#include <vector>

namespace libcrypt {

void libcrypt::Server::send_blinded_sign(int64_t mod, int64_t server_private_key, std::fstream& secure_channel)
{
    int32_t blinded_hash_part = 0;

    while (secure_channel.read(reinterpret_cast<char*>(&blinded_hash_part), sizeof(blinded_hash_part)))
    {
        const auto blinded_sign_part
            = static_cast<int32_t>(libcrypt::pow_mod(blinded_hash_part, server_private_key, mod));

        secure_channel.seekg(static_cast<int64_t>(-1 * sizeof(blinded_hash_part)), std::ios::cur);

        secure_channel.write(reinterpret_cast<const char*>(&blinded_sign_part), sizeof(blinded_sign_part));
    }
}

bool libcrypt::Server::check_bulletin(int64_t mod, int64_t server_shared_key, std::fstream& anonymous_channel)
{
    uint64_t vote = 0;

    anonymous_channel.read(reinterpret_cast<char*>(&vote), sizeof(vote));

    const std::string vote_hash = picosha2::hash256_hex_string(std::to_string(vote));

    for (const auto& hash_part : vote_hash)
    {
        int32_t signed_hash_part = 0;

        anonymous_channel.read(reinterpret_cast<char*>(&signed_hash_part), sizeof(signed_hash_part));

        if (hash_part != libcrypt::pow_mod(static_cast<int64_t>(signed_hash_part), server_shared_key, mod))
        {
            return false;
        }
    }
    return true;
}

void libcrypt::Elector::gen_blind_factor(int64_t mod)
{
    std::vector<int64_t> gcd_result;
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> blind_factor_range(2, mod - 1);

    do
    {
        blind_factor = blind_factor_range(mt);
        gcd_result = libcrypt::extended_gcd(blind_factor, mod);
    } while (gcd_result.front() != 1);

    inverse_blind_factor = gcd_result.back();

    if (inverse_blind_factor < 0)
    {
        inverse_blind_factor += mod;
    }
}

libcrypt::Elector::Elector(uint8_t answer)
{
    constexpr uint8_t excess_data_offset = 32;
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<uint64_t> excess_data_range(UINT32_MAX / 2 + 1, UINT32_MAX);
    vote = (excess_data_range(mt) << excess_data_offset) + answer;
}

std::fstream libcrypt::Server::accept_connection(libcrypt::Elector& elector)
{
    if (electors_id.contains(elector.get_elector_id()))
    {
        throw std::runtime_error{"Can't vote twice"};
    }

    elector.set_elector_id(electors_id.size());
    electors_id.emplace(electors_id.size());

    return std::fstream{
        std::to_string(electors_id.size() - 1), std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc};
}

void libcrypt::Elector::send_blinded_hash(int64_t mod, int64_t server_shared_key, std::fstream& secure_channel)
{
    gen_blind_factor(mod);

    const std::string vote_hash{picosha2::hash256_hex_string(std::to_string(vote))};

    for (const auto& hash_part : vote_hash)
    {
        const auto blinded_hash_part = static_cast<int32_t>(
            libcrypt::mod(hash_part * libcrypt::pow_mod(blind_factor, server_shared_key, mod), mod));

        secure_channel.write(reinterpret_cast<const char*>(&blinded_hash_part), sizeof(blinded_hash_part));
    }
}

void libcrypt::Elector::send_bulletin(int64_t mod, std::fstream& secure_channel, std::fstream& anonymous_channel) const
{
    anonymous_channel.write(reinterpret_cast<const char*>(&vote), sizeof(vote));

    int32_t blinded_sign_part = 0;

    while (secure_channel.read(reinterpret_cast<char*>(&blinded_sign_part), sizeof(blinded_sign_part)))
    {
        const auto sign_part = static_cast<int32_t>(libcrypt::mod(blinded_sign_part * inverse_blind_factor, mod));

        anonymous_channel.write(reinterpret_cast<const char*>(&sign_part), sizeof(sign_part));
    }
}

}  // namespace libcrypt