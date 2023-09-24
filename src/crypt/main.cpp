#include <libcrypt/utils.hpp>
#include <libcrypt/ciphers.hpp>
#include <iostream>
#include <exception>

int main()
{
    try
    {
        libcrypt::shamir("message.txt");
    }
    catch (const std::exception& msg)
    {
        std::cerr << msg.what() << '\n';
        return -1;
    }
}
