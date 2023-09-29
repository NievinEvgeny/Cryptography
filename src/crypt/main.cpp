#include <ciphers/cipher_examples.hpp>
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
        ("m,message", "message filename", cxxopts::value<std::string>()->default_value("examples/ciphers/message.txt"))
        ("e,encrypt", "encryption filename", cxxopts::value<std::string>()->default_value("examples/ciphers/encryption.txt"))
        ("d,decrypt", "decryption filename", cxxopts::value<std::string>()->default_value("examples/ciphers/decryption.txt"))
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
            if (parse_cmd_line.count("shamir"))
            {
                libcrypt::shamir_example(parse_cmd_line);
            }
            if (parse_cmd_line.count("elgamal"))
            {
                libcrypt::elgamal_example(parse_cmd_line);
            }
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
