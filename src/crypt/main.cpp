#include <libcrypt/utils.hpp>
#include <libcrypt/ciphers.hpp>
#include <iostream>
#include <exception>
#include <string>

int main()
{
    try
    {
        const std::string message_filename{"message.txt"};
        const std::string encryption_filename{"encryption.txt"};
        const std::string decryption_filename{"decryption.txt"};
        libcrypt::shamir(message_filename, encryption_filename, decryption_filename);
    }
    catch (const std::exception& msg)
    {
        std::cerr << msg.what() << '\n';
        return -1;
    }
}
