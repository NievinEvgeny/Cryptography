#pragma once
#include <cstdint>
#include <fstream>
#include <unordered_set>

namespace libcrypt {

class Server;

class Elector
{
    uint64_t vote;
    int64_t blind_factor = -1;
    int64_t inverse_blind_factor = -1;

    uint64_t elector_id = -1;  // for simulation of secure channel
                               // where server identifies elector

    void gen_blind_factor(int64_t mod);

    uint64_t get_elector_id() const
    {
        return elector_id;
    }

    void set_elector_id(uint64_t new_elector_id)
    {
        elector_id = new_elector_id;
    }

   public:
    explicit Elector(uint8_t answer);

    void send_blinded_hash(int64_t mod, int64_t server_shared_key, std::fstream& secure_channel);

    void send_bulletin(int64_t mod, std::fstream& secure_channel, std::fstream& anonymous_channel) const;

    friend libcrypt::Server;
};

class Server
{
    std::unordered_set<uint64_t> electors_id;

   public:
    std::fstream accept_connection(libcrypt::Elector& elector);

    static void send_blinded_sign(int64_t mod, int64_t server_private_key, std::fstream& secure_channel);

    static bool check_bulletin(int64_t mod, int64_t server_shared_key, std::fstream& anonymous_channel);
};

}  // namespace libcrypt