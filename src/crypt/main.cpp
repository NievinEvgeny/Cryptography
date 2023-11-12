#include <ciphers/ciphers_example.hpp>
#include <signatures/sign_example.hpp>
#include <poker/poker_example.hpp>
#include <cxxopts.hpp>
#include <iostream>
#include <exception>
#include <string>
#include <cstdint>

int main(int argc, char** argv)
{
    cxxopts::Options options("cryptography");

    // clang-format off
    options.add_options()
        ("c,cipher", "cipher call")
        ("s,sign", "sign call")
        ("p,poker", "poker call")
        ("shamir", "shamir cipher call")
        ("elgamal", "elgamal cipher/sign call")
        ("vernam", "vernam cipher call")
        ("rsa", "rsa cipher/sign call")
        ("gost", "gost sign call")
        ("players", "number of players", cxxopts::value<uint8_t>()->default_value("10"))
        ("m,message", "message filename", cxxopts::value<std::string>()->default_value("examples/ciphers/message.txt"))
        ("e,encrypt", "encryption filename", cxxopts::value<std::string>()->default_value("examples/ciphers/encryption.txt"))
        ("d,decrypt", "decryption filename", cxxopts::value<std::string>()->default_value("examples/ciphers/decryption.txt"))
        ("v,vernam_key", "vernam key filename", cxxopts::value<std::string>()->default_value("examples/ciphers/vernam_key.txt"))
        ("f,sign_file", "signature file", cxxopts::value<std::string>()->default_value("examples/signatures/file.txt"))
        ("h,help", "Print usage");
    // clang-format on

    try
    {
        const auto parse_cmd_line = options.parse(argc, argv);

        if (parse_cmd_line.count("help"))
        {
            std::cout << options.help() << '\n';
            return 0;
        }

        if (parse_cmd_line.count("cipher"))
        {
            libcrypt::cipher_call_example(parse_cmd_line);
        }

        if (parse_cmd_line.count("sign"))
        {
            if (libcrypt::sign_call_example(parse_cmd_line))
            {
                std::cout << "sign is correct\n";
            }
        }

        if (parse_cmd_line.count("poker"))
        {
            libcrypt::poker_call_example(parse_cmd_line);
        }
    }
    catch (const cxxopts::exceptions::exception& msg)
    {
        std::cerr << msg.what() << '\n';
        return -1;
    }
    catch (const std::exception& msg)
    {
        std::cerr << msg.what() << '\n';
        return -1;
    }
}
