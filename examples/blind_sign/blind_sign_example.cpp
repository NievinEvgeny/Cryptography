#include <blind_sign/blind_sign_example.hpp>
#include <params/gen_params.hpp>
#include <libcrypt/blind_sign.hpp>
#include <cxxopts.hpp>
#include <fstream>

namespace libcrypt {

bool anon_voting_call_example(const cxxopts::ParseResult& parse_cmd_line)
{
    const uint8_t answer = parse_cmd_line["answer"].as<uint8_t>();

    libcrypt::rsa_sys_params params = libcrypt::rsa_gen_sys();

    libcrypt::Server server;
    libcrypt::Elector alice(answer);

    std::fstream secure_channel{server.accept_connection(alice)};

    if (!secure_channel.is_open())
    {
        throw std::runtime_error{"can't create secure channel in anon voting\n"};
    }

    alice.send_blinded_hash(params.mod, params.user.shared_key, secure_channel);

    secure_channel.seekg(std::ios::beg);

    libcrypt::Server::send_blinded_sign(params.mod, params.user.private_key, secure_channel);

    secure_channel.clear();
    secure_channel.seekg(std::ios::beg);

    std::fstream anon_channel("result.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);

    if (!anon_channel.is_open())
    {
        throw std::runtime_error{"can't create result file in anon sign\n"};
    }

    alice.send_bulletin(params.mod, secure_channel, anon_channel);

    anon_channel.seekg(std::ios::beg);

    return libcrypt::Server::check_bulletin(params.mod, params.user.shared_key, anon_channel);
}

}  // namespace libcrypt