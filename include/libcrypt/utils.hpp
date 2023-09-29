#pragma once
#include <cstdint>
#include <vector>

namespace libcrypt {

struct dh_system_params
{
    int64_t base;
    int64_t mod;
};

bool is_prime(int64_t prime);

int64_t pow_mod(int64_t base, int64_t exp, int64_t mod);

std::vector<int64_t> extended_gcd(int64_t first, int64_t second);

libcrypt::dh_system_params gen_dh_system();

int64_t diffie_hellman(int64_t private_keyA, int64_t private_keyB);

int64_t baby_step_giant_step(int64_t base, int64_t result, int64_t mod);

}  // namespace libcrypt
