#include <libcrypt/utils.hpp>
#include <cstdint>
#include <vector>
#include <cmath>
#include <random>
#include <unordered_map>

namespace crypt {

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

static bool is_prime(int64_t prime)
{
    if (prime <= 1)
    {
        return false;
    }

    auto b = static_cast<int64_t>(std::sqrt(prime));

    for (int64_t i = 2; i <= b; ++i)
    {
        if ((prime % i) == 0)
        {
            return false;
        }
    }

    return true;
}

static crypt::dh_system_params gen_dh_system()
{
    int64_t prime = 0;
    int64_t base = 0;
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> prime_range(INT16_MAX, INT32_MAX);

    do
    {
        prime = prime_range(mt);
    } while (!is_prime(prime) || !is_prime(2 * prime + 1));

    int64_t mod = 2 * prime + 1;

    std::uniform_int_distribution<int64_t> base_range(2, prime);

    do
    {
        base = base_range(mt);
    } while (pow_mod(base, prime, mod) == 1);

    return crypt::dh_system_params{base, mod};
}

int64_t diffie_hellman(int64_t private_keyA, int64_t private_keyB)
{
    crypt::dh_system_params dh_sys_params = gen_dh_system();

    // int64_t open_keyA = pow_mod(dh_sys_params.base, private_keyA, dh_sys_params.mod);
    int64_t open_keyB = pow_mod(dh_sys_params.base, private_keyB, dh_sys_params.mod);

    int64_t shared_keyA = pow_mod(open_keyB, private_keyA, dh_sys_params.mod);
    // int64_t shared_keyB = pow_mod(open_keyA, private_keyB, dh_sys_params.mod);

    return shared_keyA;
}

int64_t baby_step_giant_step(int64_t base, int64_t result, int64_t mod)
{
    int64_t giant_step = std::ceil(std::sqrt(mod));
    int64_t base_pow_gstep = 1;

    for (int64_t i = 0; i < giant_step; i++)
    {
        base_pow_gstep = (base_pow_gstep * base) % mod;
    }

    std::unordered_map<int64_t, int64_t> giant_step_table;

    for (int64_t i = 1, cur = base_pow_gstep; i <= giant_step; i++)
    {
        giant_step_table[cur] = i;
        cur = (cur * base_pow_gstep) % mod;
    }

    for (int64_t j = 0, cur = result; j <= giant_step; j++)
    {
        if (giant_step_table.contains(cur))
        {
            return giant_step_table.at(cur) * giant_step - j;
        }

        cur = (cur * base) % mod;
    }

    return -1;
}

}  // namespace crypt