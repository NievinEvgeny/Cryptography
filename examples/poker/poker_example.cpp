#include <poker/poker_example.hpp>
#include <libcrypt/poker.hpp>
#include <libcrypt/utils.hpp>
#include <cxxopts.hpp>
#include <deque>
#include <cstdint>
#include <exception>

namespace libcrypt {

void poker_call_example(const cxxopts::ParseResult& parse_cmd_line)
{
    constexpr uint8_t player_hand_size = 2;
    constexpr uint8_t deck_size = 52;
    constexpr uint8_t max_players = 10;
    constexpr uint8_t board_size = 5;
    const uint8_t players_num = parse_cmd_line["players"].as<uint8_t>();

    if (players_num > max_players || players_num < 2)
    {
        throw std::runtime_error{"Number of players must be in range 2<=X<=10"};
    }

    int64_t mod = libcrypt::gen_germain_prime() * 2 + 1;

    std::deque<int64_t> card_deck;

    for (int64_t i = 2; i < deck_size + 2; i++)
    {
        card_deck.emplace_back(i);
    }

    std::deque<libcrypt::Player> players;

    for (uint8_t i = 0; i < players_num; i++)
    {
        players.emplace_back(mod);
        players.back().deck_encryption(card_deck, mod);
    }

    for (auto& player : players)
    {
        player = std::deque<int64_t>{card_deck.begin(), card_deck.begin() + player_hand_size};
        card_deck.erase(card_deck.begin(), card_deck.begin() + player_hand_size);
    }

    for (std::size_t i = 0; i < players.size(); i++)
    {
        for (std::size_t j = 0; j < players.size(); j++)
        {
            if (i != j)
            {
                players[j].deck_decryption(players[i].get_cards(), mod);
            }
        }

        players[i].deck_decryption(players[i].get_cards(), mod);
    }

    std::deque<int64_t> board{card_deck.begin(), card_deck.begin() + board_size};

    for (const auto& player : players)
    {
        player.deck_decryption(board, mod);
    }
}

}  // namespace libcrypt