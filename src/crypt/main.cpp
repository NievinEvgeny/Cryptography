#include <libcrypt/utils.hpp>
#include <iostream>
#include <cstdint>

int main()
{
    const int64_t base = -37612783631;
    const int64_t exp = 645813790211;
    const int64_t mod = 64581;

    int64_t result = crypt::pow_mod(base, exp, mod);

    std::cout << result << '\n';

    const int64_t first = 3124312425;
    const int64_t second = 1524345121234;

    std::vector<int64_t> res = crypt::extended_gcd(first, second);

    for (const auto& elem : res)
    {
        std::cout << elem << ' ';
    }
    std::cout << '\n';

    const int64_t private_keyA = 1781234;
    const int64_t private_keyB = 89102734;

    int64_t shared_key = crypt::diffie_hellman(private_keyA, private_keyB);

    std::cout << "key: " << shared_key << '\n';

    const int64_t base2 = -37612783631;
    const int64_t answer = -57623;
    const int64_t mod2 = 64581;

    int64_t exp_x = crypt::baby_step_giant_step(base2, answer, mod2);

    std::cout << exp_x << '\n';
}
