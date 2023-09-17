#include <libcrypt/utils.hpp>
#include <gtest/gtest.h>
#include <vector>

TEST(pow_mod, simple)
{
    constexpr int64_t expected = 342;

    constexpr int64_t base = 595;
    constexpr int64_t exp = 703;
    constexpr int64_t mod = 991;

    int64_t real = libcrypt::pow_mod(base, exp, mod);

    EXPECT_EQ(real, expected);
}

TEST(pow_mod, big_nums)
{
    constexpr int64_t expected = 57623;

    constexpr int64_t base = 37612783631;
    constexpr int64_t exp = 645813790211;
    constexpr int64_t mod = 64581;

    int64_t real = libcrypt::pow_mod(base, exp, mod);

    EXPECT_EQ(real, expected);
}

TEST(pow_mod, negative_nums)
{
    constexpr int64_t expected = -57623;

    constexpr int64_t base = -37612783631;
    constexpr int64_t exp = 645813790211;
    constexpr int64_t mod = 64581;

    int64_t real = libcrypt::pow_mod(base, exp, mod);

    EXPECT_EQ(real, expected);
}

TEST(pow_mod, zero_pow_zero)
{
    constexpr int64_t expected = 1;

    constexpr int64_t base = 0;
    constexpr int64_t exp = 0;
    constexpr int64_t mod = 5;

    int64_t real = libcrypt::pow_mod(base, exp, mod);

    EXPECT_EQ(real, expected);
}

TEST(extended_gcd, simple)
{
    const std::vector<int64_t> expected{2, -9, 47};

    constexpr int64_t first = 240;
    constexpr int64_t second = 46;

    std::vector<int64_t> real = libcrypt::extended_gcd(first, second);

    for (int i = 0; i < 3; i++)
    {
        EXPECT_EQ(real.at(i), expected.at(i));
    }
}

TEST(extended_gcd, big_nums)
{
    const std::vector<int64_t> expected{13, -30561593, 14910933623};

    constexpr int64_t first = 1524345121234;
    constexpr int64_t second = 3124312425;

    std::vector<int64_t> real = libcrypt::extended_gcd(first, second);

    for (int i = 0; i < 3; i++)
    {
        EXPECT_EQ(real.at(i), expected.at(i));
    }
}

TEST(extended_gcd, first_greater_than_second)
{
    const std::vector<int64_t> expected{13, -30561593, 14910933623};

    constexpr int64_t first = 3124312425;
    constexpr int64_t second = 1524345121234;

    std::vector<int64_t> real = libcrypt::extended_gcd(first, second);

    for (int i = 0; i < 3; i++)
    {
        EXPECT_EQ(real.at(i), expected.at(i));
    }
}

TEST(baby_step_giant_step, simple)
{
    constexpr int64_t expected = 832;

    constexpr int64_t base = 7;
    constexpr int64_t answer = 777;
    constexpr int64_t mod = 14947;

    int64_t real = libcrypt::baby_step_giant_step(base, answer, mod);

    EXPECT_EQ(real, expected);
}

TEST(baby_step_giant_step, big_nums)
{
    constexpr int64_t expected = 64991;

    constexpr int64_t base = -37612783631;
    constexpr int64_t answer = -57623;
    constexpr int64_t mod = 64581;

    int64_t real = libcrypt::baby_step_giant_step(base, answer, mod);

    EXPECT_EQ(real, expected);
}

TEST(baby_step_giant_step, non_relative_prime_nums)
{
    constexpr int64_t expected = -1;

    constexpr int64_t base = 4;
    constexpr int64_t answer = 776;
    constexpr int64_t mod = 14947;

    int64_t real = libcrypt::baby_step_giant_step(base, answer, mod);

    EXPECT_EQ(real, expected);
}
