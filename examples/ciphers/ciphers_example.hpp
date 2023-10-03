#pragma once
#include <libcrypt/ciphers.hpp>
#include <cxxopts.hpp>

namespace libcrypt {

struct shamir_user_params
{
    int64_t relative_prime;
    int64_t inversion;
};

void cipher_call_example(const cxxopts::ParseResult& parse_cmd_line);

}  // namespace libcrypt