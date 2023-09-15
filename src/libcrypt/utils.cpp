#include <libcrypt/utils.hpp>
#include <cstdint>

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