#include <libcrypt/utils.hpp>
#include <iostream>
#include <cstdint>

int main()
{
    constexpr int64_t base = -37612783631;
    constexpr int64_t exp = 645813790211;
    constexpr int64_t mod = 64581;

    int64_t result = libcrypt::pow_mod(base, exp, mod);

    std::cout << result << '\n';

    constexpr int64_t first = 3124312425;
    constexpr int64_t second = 1524345121234;

    std::vector<int64_t> res = libcrypt::extended_gcd(first, second);

    for (const auto& elem : res)
    {
        std::cout << elem << ' ';
    }
    std::cout << '\n';

    constexpr int64_t private_keyA = 1781234;
    constexpr int64_t private_keyB = 89102734;

    int64_t shared_key = libcrypt::diffie_hellman(private_keyA, private_keyB);

    std::cout << "key: " << shared_key << '\n';

    constexpr int64_t base2 = -37612783631;
    constexpr int64_t answer = -57623;
    constexpr int64_t mod2 = 64581;

    int64_t exp_x = libcrypt::baby_step_giant_step(base2, answer, mod2);

    std::cout << exp_x << '\n';
}
