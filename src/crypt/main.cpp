#include <libcrypt/utils.hpp>
#include <iostream>
#include <cstdint>

int main()
{
    const int64_t base = -37612783631;
    const int64_t exp = 645813790211;
    const int64_t mod = 64581;

    int64_t result = pow_mod(base, exp, mod);

    std::cout << result << '\n';

    const int64_t first = 3124312425;
    const int64_t second = 1524345121234;

    std::vector<int64_t> res = extended_gcd(first, second);

    for (const auto& elem : res)
    {
        std::cout << elem << ' ';
    }
    std::cout << '\n';
}
