#include <ciphers/ciphers_example.hpp>
#include <libcrypt/utils.hpp>
#include <libcrypt/ciphers.hpp>
#include <cxxopts.hpp>
#include <iostream>
#include <exception>
#include <string>

int main(int argc, char** argv)
{
    cxxopts::Options options("cryptography");

    // clang-format off
    options.add_options()
        ("c,cipher", "cipher call")
        ("shamir", "shamir cipher call")
        ("elgamal", "elgamal cipher call")
        ("vernam", "vernam cipher call")
        ("rsa", "rsa cipher call")
        ("m,message", "message filename", cxxopts::value<std::string>()->default_value("examples/ciphers/message.txt"))
        ("e,encrypt", "encryption filename", cxxopts::value<std::string>()->default_value("examples/ciphers/encryption.txt"))
        ("d,decrypt", "decryption filename", cxxopts::value<std::string>()->default_value("examples/ciphers/decryption.txt"))
        ("v,vernam_key", "vernam key filename", cxxopts::value<std::string>()->default_value("examples/ciphers/vernam_key.txt"))
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
