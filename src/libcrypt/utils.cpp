#include <libcrypt/utils.hpp>
#include <cstdint>
#include <vector>
#include <iostream>

int64_t pow_mod(int64_t base, int64_t exp, int64_t mod)
{
    {
        int64_t result = 1;
        base %= mod;
        while (exp)
        {
            if (exp & 1)
            {
                result = (result * base) % mod;
            }
            base = (base * base) % mod;
            exp >>= 1;
        }
        return result;
    }
}

std::vector<int64_t> extended_gcd(int64_t first, int64_t second)
{
    if (first < second)
    {
        std::swap(first, second);
    }

    std::vector<int64_t> u{first, 1, 0};
    std::vector<int64_t> v{second, 0, 1};

    while (v.front() != 0)
    {
        int64_t q = u.front() / v.front();
        std::vector<int64_t> t{u.front() % v.front(), u.at(1) - q * v.at(1), u.back() - q * v.back()};
        u = std::move(v);
        v = std::move(t);
    }

    return u;
}