#include <libcrypt/utils.hpp>
#include <libcrypt/ciphers.hpp>
#include <PicoSHA2/picosha2.h>
#include <gtest/gtest.h>
#include <string>
#include <filesystem>
#include <fstream>
#include <random>
#include <cstdint>
#include <climits>

struct shamir_user_params
{
    int64_t relative_prime;
    int64_t inversion;
};

static shamir_user_params shamir_gen_user_params(int64_t mod)
{
    int64_t relative_prime = 0;
    std::vector<int64_t> gcd_result;

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> rel_prime_range(INT16_MAX, mod - 1);

    do
    {
        relative_prime = rel_prime_range(mt);
        gcd_result = libcrypt::extended_gcd(mod - 1, relative_prime);
    } while (gcd_result.front() != 1);

    int64_t inversion = gcd_result.back();

    if (inversion < 0)
    {
        inversion += mod - 1;
    }

    return {relative_prime, inversion};
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
    int64_t mod = 0;
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> mod_range(INT16_MAX, INT32_MAX);

    do
    {
        mod = mod_range(mt);
    } while (!libcrypt::is_prime(mod));

    const shamir_user_params sender_params = shamir_gen_user_params(mod);
    const shamir_user_params reciever_params = shamir_gen_user_params(mod);

    for (auto& file : files)
    {
        file.clear();
        file.seekg(std::ios::beg);

        std::fstream encryption_file(
            temp_dir + "/shamir_e.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);

        std::ofstream decryption_file_out(temp_dir + "/shamir_d.txt", std::ios::binary);

        if (!file.is_open() || !encryption_file.is_open() || !decryption_file_out.is_open())
        {
            throw std::runtime_error{"Can't open file in shamir's cipher test"};
        }

        libcrypt::shamir_encrypt(
            mod, reciever_params.relative_prime, sender_params.relative_prime, file, encryption_file);

        encryption_file.clear();
        encryption_file.seekp(0, std::ios::beg);

        libcrypt::shamir_decrypt(
            mod, reciever_params.inversion, sender_params.inversion, encryption_file, decryption_file_out);

        decryption_file_out.close();

        std::ifstream decryption_file_in(temp_dir + "/shamir_d.txt", std::ios::binary);

        if (!decryption_file_in.is_open())
        {
            throw std::runtime_error{"Can't open file in shamir's cipher test"};
        }

        file.clear();
        file.seekg(std::ios::beg);

        picosha2::hash256_one_by_one message_hasher;
        message_hasher.process(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        message_hasher.finish();
        std::string message_hash;
        picosha2::get_hash_hex_string(message_hasher, message_hash);

        picosha2::hash256_one_by_one decryption_hasher;
        decryption_hasher.process(std::istreambuf_iterator<char>(decryption_file_in), std::istreambuf_iterator<char>());
        decryption_hasher.finish();
        std::string decrypted_hash;
        picosha2::get_hash_hex_string(decryption_hasher, decrypted_hash);

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
    libcrypt::dh_system_params sys_params = libcrypt::gen_dh_system();

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> private_key_range(2, sys_params.mod - 2);
    std::uniform_int_distribution<int64_t> session_key_range(1, sys_params.mod - 2);

    int64_t recv_private_key = private_key_range(mt);
    int64_t recv_shared_key = libcrypt::pow_mod(sys_params.base, recv_private_key, sys_params.mod);
    int64_t session_key = session_key_range(mt);

    for (auto& file : files)
    {
        file.clear();
        file.seekg(std::ios::beg);

        std::fstream encryption_file(
            temp_dir + "/elgamal_e.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);

        std::ofstream decryption_file_out(temp_dir + "/elgamal_d.txt", std::ios::binary);

        if (!file.is_open() || !encryption_file.is_open() || !decryption_file_out.is_open())
        {
            throw std::runtime_error{"Can't open file in elgamal's cipher test"};
        }

        libcrypt::elgamal_encrypt(sys_params, session_key, recv_shared_key, file, encryption_file);

        encryption_file.clear();
        encryption_file.seekp(0, std::ios::beg);

        libcrypt::elgamal_decrypt(sys_params.mod, recv_private_key, encryption_file, decryption_file_out);

        decryption_file_out.close();

        std::ifstream decryption_file_in(temp_dir + "/elgamal_d.txt", std::ios::binary);

        if (!decryption_file_in.is_open())
        {
            throw std::runtime_error{"Can't open file in elgamal's cipher test"};
        }

        file.clear();
        file.seekg(std::ios::beg);

        picosha2::hash256_one_by_one message_hasher;
        message_hasher.process(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        message_hasher.finish();
        std::string message_hash;
        picosha2::get_hash_hex_string(message_hasher, message_hash);

        picosha2::hash256_one_by_one decryption_hasher;
        decryption_hasher.process(std::istreambuf_iterator<char>(decryption_file_in), std::istreambuf_iterator<char>());
        decryption_hasher.finish();
        std::string decrypted_hash;
        picosha2::get_hash_hex_string(decryption_hasher, decrypted_hash);

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
        file.clear();
        file.seekg(std::ios::beg);

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

        picosha2::hash256_one_by_one message_hasher;
        message_hasher.process(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        message_hasher.finish();
        std::string message_hash;
        picosha2::get_hash_hex_string(message_hasher, message_hash);

        picosha2::hash256_one_by_one decryption_hasher;
        decryption_hasher.process(std::istreambuf_iterator<char>(decryption_file_in), std::istreambuf_iterator<char>());
        decryption_hasher.finish();
        std::string decrypted_hash;
        picosha2::get_hash_hex_string(decryption_hasher, decrypted_hash);

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
    constexpr int64_t recv_shared_key = 3;
    std::vector<int64_t> gcd_result;

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int64_t> prime_gen_range(UINT8_MAX, INT16_MAX);

    int64_t mod_part_P = 0;
    int64_t mod_part_Q = 0;
    int64_t euler_func_res = 0;

    do
    {
        do
        {
            mod_part_P = prime_gen_range(mt);
        } while (!libcrypt::is_prime(mod_part_P));

        do
        {
            mod_part_Q = prime_gen_range(mt);
        } while (!libcrypt::is_prime(mod_part_Q));

        euler_func_res = (mod_part_P - 1) * (mod_part_Q - 1);
        gcd_result = libcrypt::extended_gcd(recv_shared_key, euler_func_res);
    } while (gcd_result.front() != 1);

    int64_t mod = mod_part_P * mod_part_Q;
    int64_t recv_private_key = gcd_result.back();

    if (recv_private_key < 0)
    {
        recv_private_key += euler_func_res;
    }

    for (auto& file : files)
    {
        file.clear();
        file.seekg(std::ios::beg);

        std::fstream encryption_file(
            temp_dir + "/rsa_e.txt", std::ios::binary | std::ios::out | std::ios::in | std::ios::trunc);

        std::ofstream decryption_file_out(temp_dir + "/rsa_d.txt", std::ios::binary);

        if (!file.is_open() || !encryption_file.is_open() || !decryption_file_out.is_open())
        {
            throw std::runtime_error{"Can't open file in rsa cipher test"};
        }

        libcrypt::rsa_encrypt(mod, recv_shared_key, file, encryption_file);

        encryption_file.clear();
        encryption_file.seekp(0, std::ios::beg);

        libcrypt::rsa_decrypt(mod, recv_private_key, encryption_file, decryption_file_out);

        decryption_file_out.close();

        std::ifstream decryption_file_in(temp_dir + "/rsa_d.txt", std::ios::binary);

        if (!decryption_file_in.is_open())
        {
            throw std::runtime_error{"Can't open file in rsa cipher test"};
        }

        file.clear();
        file.seekg(std::ios::beg);

        picosha2::hash256_one_by_one message_hasher;
        message_hasher.process(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        message_hasher.finish();
        std::string message_hash;
        picosha2::get_hash_hex_string(message_hasher, message_hash);

        picosha2::hash256_one_by_one decryption_hasher;
        decryption_hasher.process(std::istreambuf_iterator<char>(decryption_file_in), std::istreambuf_iterator<char>());
        decryption_hasher.finish();
        std::string decrypted_hash;
        picosha2::get_hash_hex_string(decryption_hasher, decrypted_hash);

        ASSERT_EQ(message_hash, decrypted_hash);

        file.close();
        encryption_file.close();
        decryption_file_in.close();
        std::filesystem::remove(temp_dir + "/rsa_e.txt");
        std::filesystem::remove(temp_dir + "/rsa_d.txt");
    }
}
