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
}
