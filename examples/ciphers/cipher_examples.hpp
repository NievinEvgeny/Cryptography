#pragma once
#include <libcrypt/ciphers.hpp>
#include <cxxopts.hpp>

namespace libcrypt {

struct shamir_user_params
{
    int64_t relative_prime;
    int64_t inversion;
};

void shamir_example(const cxxopts::ParseResult& parse_cmd_line);

void elgamal_example(const cxxopts::ParseResult& parse_cmd_line);

}  // namespace libcrypt