#include <libcrypt/utils.hpp>
#include <libcrypt/ciphers.hpp>
#include <params/gen_params.hpp>
#include <PicoSHA2/picosha2.h>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <filesystem>
#include <iterator>
#include <fstream>
#include <random>
#include <cstdint>
#include <climits>

namespace {

std::string calc_file_hash(std::ifstream& file)
{
    std::vector<unsigned char> bin_file_hash(picosha2::k_digest_size);
    picosha2::hash256(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>(),
        bin_file_hash.begin(),
        bin_file_hash.end());
    return picosha2::bytes_to_hex_string(bin_file_hash.begin(), bin_file_hash.end());
}

class CiphersTest : public testing::Test
{
   protected:
    const std::string temp_dir = std::filesystem::temp_directory_path().string();

    std::vector<std::ifstream> files;

    std::uint64_t vernam_key_max_size;

    virtual void SetUp()
    {
        constexpr int small_size = 1000;
        constexpr int medium_size = 256000;
        constexpr int big_size = 2048000;

        vernam_key_max_size = big_size;

        std::random_device rd;
        std::mt19937 mt(rd());
        std::uniform_int_distribution<int16_t> num_gen_range(CHAR_MIN, CHAR_MAX);

        std::ofstream small_file_out(temp_dir + "/small.txt", std::ios::binary);
        std::ofstream medium_file_out(temp_dir + "/medium.txt", std::ios::binary);
        std::ofstream big_file_out(temp_dir + "/big.txt", std::ios::binary);

        if (!small_file_out.is_open() || !medium_file_out.is_open() || !big_file_out.is_open())
        {
            throw std::runtime_error{"Can't open file in cipher's SetUp"};
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

        files.emplace_back(std::ifstream{temp_dir + "/small.txt", std::ios::binary});
        files.emplace_back(std::ifstream{temp_dir + "/medium.txt", std::ios::binary});
        files.emplace_back(std::ifstream{temp_dir + "/big.txt", std::ios::binary});
    }

    virtual void TearDown()
    {
        std::filesystem::remove(temp_dir + "/small.txt");
        std::filesystem::remove(temp_dir + "/medium.txt");
        std::filesystem::remove(temp_dir + "/big.txt");
    }
};

TEST_F(CiphersTest, shamir_with_different_files_size)
{
    libcrypt::shamir_sys_params params = libcrypt::shamir_gen_sys();

    for (auto& file : files)
    {
        std::fstream encryption_file(
            temp_dir + "/shamir_e.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);

        std::ofstream decryption_file_out(temp_dir + "/shamir_d.txt", std::ios::binary);

        if (!file.is_open() || !encryption_file.is_open() || !decryption_file_out.is_open())
        {
            throw std::runtime_error{"Can't open file in shamir's cipher test"};
        }

        libcrypt::shamir_encrypt(params.mod, params.recv.private_key, params.send.private_key, file, encryption_file);

        encryption_file.clear();
        encryption_file.seekp(0, std::ios::beg);

        libcrypt::shamir_decrypt(
            params.mod, params.recv.shared_key, params.send.shared_key, encryption_file, decryption_file_out);

        decryption_file_out.close();

        std::ifstream decryption_file_in(temp_dir + "/shamir_d.txt", std::ios::binary);

        if (!decryption_file_in.is_open())
        {
            throw std::runtime_error{"Can't open file in shamir's cipher test"};
        }

        file.clear();
        file.seekg(std::ios::beg);

        std::string message_hash{calc_file_hash(file)};
        std::string decrypted_hash{calc_file_hash(decryption_file_in)};

        ASSERT_EQ(message_hash, decrypted_hash);

        file.close();
        encryption_file.close();
        decryption_file_in.close();
        std::filesystem::remove(temp_dir + "/shamir_e.txt");
        std::filesystem::remove(temp_dir + "/shamir_d.txt");
    }
}

TEST_F(CiphersTest, elgamal_with_different_files_size)
{
    libcrypt::elgamal_sys_params params = libcrypt::elgamal_gen_sys();

    for (auto& file : files)
    {
        std::fstream encryption_file(
            temp_dir + "/elgamal_e.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);

        std::ofstream decryption_file_out(temp_dir + "/elgamal_d.txt", std::ios::binary);

        if (!file.is_open() || !encryption_file.is_open() || !decryption_file_out.is_open())
        {
            throw std::runtime_error{"Can't open file in elgamal's cipher test"};
        }

        libcrypt::elgamal_encrypt(
            params.dh_sys_params, params.session_key, params.user.shared_key, file, encryption_file);

        encryption_file.clear();
        encryption_file.seekp(0, std::ios::beg);

        libcrypt::elgamal_decrypt(
            params.dh_sys_params.mod, params.user.private_key, encryption_file, decryption_file_out);

        decryption_file_out.close();

        std::ifstream decryption_file_in(temp_dir + "/elgamal_d.txt", std::ios::binary);

        if (!decryption_file_in.is_open())
        {
            throw std::runtime_error{"Can't open file in elgamal's cipher test"};
        }

        file.clear();
        file.seekg(std::ios::beg);

        std::string message_hash{calc_file_hash(file)};
        std::string decrypted_hash{calc_file_hash(decryption_file_in)};

        ASSERT_EQ(message_hash, decrypted_hash);

        file.close();
        encryption_file.close();
        decryption_file_in.close();
        std::filesystem::remove(temp_dir + "/elgamal_e.txt");
        std::filesystem::remove(temp_dir + "/elgamal_d.txt");
    }
}

TEST_F(CiphersTest, vernam_with_different_files_size)
{
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int16_t> randomizer(CHAR_MIN, CHAR_MAX);

    for (auto& file : files)
    {
        std::fstream vernam_key_file(
            temp_dir + "/vernam_key.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);

        std::fstream encryption_file(
            temp_dir + "/vernam_e.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);

        std::ofstream decryption_file_out(temp_dir + "/vernam_d.txt", std::ios::binary);

        if (!file.is_open() || !encryption_file.is_open() || !decryption_file_out.is_open()
            || !vernam_key_file.is_open())
        {
            throw std::runtime_error{"Can't open file in vernam's cipher test"};
        }

        for (uintmax_t i = 0; i < vernam_key_max_size; i++)
        {
            char rand = static_cast<char>(randomizer(mt));
            vernam_key_file.write(reinterpret_cast<const char*>(&rand), sizeof(char));
        }

        vernam_key_file.seekp(0, std::ios::beg);

        libcrypt::vernam_encrypt(vernam_key_file, file, encryption_file);

        encryption_file.seekp(0, std::ios::beg);
        vernam_key_file.clear();
        vernam_key_file.seekp(0, std::ios::beg);

        libcrypt::vernam_decrypt(vernam_key_file, encryption_file, decryption_file_out);

        decryption_file_out.close();

        std::ifstream decryption_file_in(temp_dir + "/vernam_d.txt", std::ios::binary);

        if (!decryption_file_in.is_open())
        {
            throw std::runtime_error{"Can't open file in vernam's cipher test"};
        }

        file.clear();
        file.seekg(std::ios::beg);

        std::string message_hash{calc_file_hash(file)};
        std::string decrypted_hash{calc_file_hash(decryption_file_in)};

        ASSERT_EQ(message_hash, decrypted_hash);

        file.close();
        vernam_key_file.close();
        encryption_file.close();
        decryption_file_in.close();
        std::filesystem::remove(temp_dir + "/vernam_key.txt");
        std::filesystem::remove(temp_dir + "/vernam_e.txt");
        std::filesystem::remove(temp_dir + "/vernam_d.txt");
    }
}

TEST_F(CiphersTest, rsa_with_different_files_size)
{
    libcrypt::rsa_sys_params params = libcrypt::rsa_gen_sys();

    for (auto& file : files)
    {
        std::fstream encryption_file(
            temp_dir + "/rsa_e.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);

        std::ofstream decryption_file_out(temp_dir + "/rsa_d.txt", std::ios::binary);

        if (!file.is_open() || !encryption_file.is_open() || !decryption_file_out.is_open())
        {
            throw std::runtime_error{"Can't open file in rsa cipher test"};
        }

        libcrypt::rsa_encrypt(params.mod, params.user.shared_key, file, encryption_file);

        encryption_file.clear();
        encryption_file.seekp(0, std::ios::beg);

        libcrypt::rsa_decrypt(params.mod, params.user.private_key, encryption_file, decryption_file_out);

        decryption_file_out.close();

        std::ifstream decryption_file_in(temp_dir + "/rsa_d.txt", std::ios::binary);

        if (!decryption_file_in.is_open())
        {
            throw std::runtime_error{"Can't open file in rsa cipher test"};
        }

        file.clear();
        file.seekg(std::ios::beg);

        std::string message_hash{calc_file_hash(file)};
        std::string decrypted_hash{calc_file_hash(decryption_file_in)};

        ASSERT_EQ(message_hash, decrypted_hash);

        file.close();
        encryption_file.close();
        decryption_file_in.close();
        std::filesystem::remove(temp_dir + "/rsa_e.txt");
        std::filesystem::remove(temp_dir + "/rsa_d.txt");
    }
}

}  // namespace
