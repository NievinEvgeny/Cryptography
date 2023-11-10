#pragma once
#include <cstdint>
#include <deque>

namespace libcrypt {

class Player
{
    int64_t key_c;
    int64_t key_d;
    std::deque<int64_t> cards;

   public:
    explicit Player(int64_t mod);

    Player& operator=(const std::deque<int64_t>& other_cards)
    {
        cards = other_cards;
        return *this;
    }

    Player& operator=(std::deque<int64_t>&& other_cards)
    {
        cards = std::move(other_cards);
        return *this;
    }

    std::deque<int64_t>& get_cards()
    {
        return cards;
    }

    static void shuffle(std::deque<int64_t>& card_deck);

    void deck_encryption(std::deque<int64_t>& card_deck, int64_t mod) const;

    void deck_decryption(std::deque<int64_t>& card_deck, int64_t mod) const;
};

}  // namespace libcrypt