#pragma once
#include <cstdint>
#include <vector>

namespace crypt {

struct dh_system_params
{
    int64_t base;
    int64_t mod;
};

int64_t pow_mod(int64_t base, int64_t exp, int64_t mod);

std::vector<int64_t> extended_gcd(int64_t first, int64_t second);

int64_t diffie_hellman(int64_t private_keyA, int64_t private_keyB);

}  // namespace crypt
