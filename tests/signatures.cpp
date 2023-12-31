#include <params/gen_params.hpp>
#include <libcrypt/signatures.hpp>
#include <libcrypt/blind_sign.hpp>
#include <PicoSHA2/picosha2.h>
#include <gtest/gtest.h>
#include <string>
#include <filesystem>
#include <fstream>
#include <random>
#include <exception>
#include <cstdint>
#include <vector>
#include <climits>

namespace {

class SignaturesTest : public testing::Test
{
   protected:
    const std::string temp_dir = std::filesystem::temp_directory_path().string();

    std::vector<std::fstream> files;

    virtual void SetUp()
    {
        constexpr int small_size = 1000;
        constexpr int medium_size = 256000;
        constexpr int big_size = 2048000;

        std::random_device rd;
        std::mt19937 mt(rd());
        std::uniform_int_distribution<int16_t> num_gen_range(CHAR_MIN, CHAR_MAX);

        std::ofstream small_file_out(temp_dir + "/small.txt", std::ios::binary);
        std::ofstream medium_file_out(temp_dir + "/medium.txt", std::ios::binary);
        std::ofstream big_file_out(temp_dir + "/big.txt", std::ios::binary);

        if (!small_file_out.is_open() || !medium_file_out.is_open() || !big_file_out.is_open())
        {
            throw std::runtime_error{"Can't open file in signatures's SetUp"};
        }

        for (int i = 0; i < big_size; i++)
        {
            char generated_num = num_gen_range(mt);

            big_file_out.write(reinterpret_cast<const char*>(&generated_num), sizeof(char));

            if (i < medium_size)
            {
                medium_file_out.write(reinterpret_cast<const char*>(&generated_num), sizeof(char));
            }

            if (i < small_size)
            {
                small_file_out.write(reinterpret_cast<const char*>(&generated_num), sizeof(char));
            }
        }

        small_file_out.close();
        medium_file_out.close();
        big_file_out.close();

        files.emplace_back(std::fstream{temp_dir + "/small.txt", std::ios::binary | std::ios::in | std::ios::out});
        files.emplace_back(std::fstream{temp_dir + "/medium.txt", std::ios::binary | std::ios::in | std::ios::out});
        files.emplace_back(std::fstream{temp_dir + "/big.txt", std::ios::binary | std::ios::in | std::ios::out});

        for (const auto& file : files)
        {
            if (!file.is_open())
            {
                throw std::runtime_error{"Can't open file in signatures's SetUp"};
            }
        }
    }

    virtual void TearDown()
    {
        std::filesystem::remove(temp_dir + "/small.txt");
        std::filesystem::remove(temp_dir + "/medium.txt");
        std::filesystem::remove(temp_dir + "/big.txt");
    }
};

TEST_F(SignaturesTest, rsa_with_different_files_size)
{
    libcrypt::rsa_sys_params params = libcrypt::rsa_gen_sys();

    for (auto& file : files)
    {
        libcrypt::rsa_file_signing(params.mod, params.user.private_key, file);

        file.seekg(std::ios::beg);

        ASSERT_TRUE(libcrypt::rsa_check_file_sign(params.mod, params.user.shared_key, file));

        file.close();
    }
}

TEST_F(SignaturesTest, elgamal_with_different_files_size)
{
    libcrypt::elgamal_sys_params params = libcrypt::elgamal_gen_sys();

    for (auto& file : files)
    {
        libcrypt::elgamal_file_signing(params.dh_sys_params, params.session_key, params.user.private_key, file);

        file.seekg(std::ios::beg);

        ASSERT_TRUE(libcrypt::elgamal_check_file_sign(params.dh_sys_params, params.user.shared_key, file));

        file.close();
    }
}

TEST_F(SignaturesTest, gost_with_different_files_size)
{
    libcrypt::gost_sys_params params = libcrypt::gost_gen_sys();

    for (auto& file : files)
    {
        libcrypt::gost_file_signing(
            params.mod, params.elliptic_exp, params.elliptic_coef, params.user.private_key, file);

        file.seekg(std::ios::beg);

        ASSERT_TRUE(libcrypt::gost_check_file_sign(
            params.mod, params.elliptic_exp, params.elliptic_coef, params.user.shared_key, file));

        file.close();
    }
}

TEST_F(SignaturesTest, anon_voting_on_different_files)
{
    constexpr uint8_t answer = 1;

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

    std::fstream anon_channel(
        temp_dir + "/result.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);

    if (!anon_channel.is_open())
    {
        throw std::runtime_error{"can't create result file in anon sign\n"};
    }

    alice.send_bulletin(params.mod, secure_channel, anon_channel);

    anon_channel.seekg(std::ios::beg);

    ASSERT_TRUE(libcrypt::Server::check_bulletin(params.mod, params.user.shared_key, anon_channel));

    secure_channel.close();
    anon_channel.close();
    std::filesystem::remove("0");
    std::filesystem::remove(temp_dir + "result.txt");
}

TEST_F(SignaturesTest, repetitive_voting_attempt)
{
    constexpr uint8_t answer = 1;

    libcrypt::Server server;
    libcrypt::Elector alice(answer);

    std::fstream secure_channel{server.accept_connection(alice)};
    ASSERT_ANY_THROW(server.accept_connection(alice));

    secure_channel.close();
    std::filesystem::remove("0");
}

}  // namespace