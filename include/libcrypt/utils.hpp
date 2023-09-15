#pragma once
#include <cstdint>
#include <vector>

int64_t pow_mod(int64_t base, int64_t exp, int64_t mod);

std::vector<int64_t> extended_gcd(int64_t first, int64_t second);
