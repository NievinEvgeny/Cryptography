#include <libcrypt/poker.hpp>
#include <libcrypt/utils.hpp>
#include <algorithm>
#include <cstdint>
#include <random>

namespace libcrypt {

libcrypt::Player::Player(int64_t mod)
{
    std::vector<int64_t> gcd_result;
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> key_c_range(2, mod - 2);

    do
    {
        key_c = key_c_range(mt);
        gcd_result = libcrypt::extended_gcd(key_c, mod - 1);
    } while (gcd_result.front() != 1);

    key_d = gcd_result.back();

    if (key_d < 0)
    {
        key_d += mod - 1;
    }
}

void libcrypt::Player::shuffle(std::deque<int64_t>& card_deck)
{
    std::random_device rd;
    std::mt19937 mt(rd());
    std::shuffle(card_deck.begin(), card_deck.end(), mt);
}

void libcrypt::Player::deck_encryption(std::deque<int64_t>& card_deck, int64_t mod) const
{
    for (auto& card : card_deck)
    {
        card = libcrypt::pow_mod(card, key_c, mod);
    }

    Player::shuffle(card_deck);
}

void libcrypt::Player::deck_decryption(std::deque<int64_t>& card_deck, int64_t mod) const
{
    for (auto& card : card_deck)
    {
        card = libcrypt::pow_mod(card, key_d, mod);
    }
}

}  // namespace libcrypt