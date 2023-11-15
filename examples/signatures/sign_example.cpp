#include <signatures/sign_example.hpp>
#include <libcrypt/signatures.hpp>
#include <params/gen_params.hpp>
#include <cxxopts.hpp>
#include <filesystem>
#include <string>
#include <fstream>
#include <exception>

namespace libcrypt {

bool sign_call_example(const cxxopts::ParseResult& parse_cmd_line)
{
    const std::filesystem::path signature_filepath = parse_cmd_line["sign_file"].as<std::string>();

    std::fstream sign_file(signature_filepath, std::ios::binary | std::ios::out | std::ios::in | std::ios::app);
    if (!sign_file.is_open())
    {
        throw std::runtime_error{'"' + signature_filepath.string() + '"' + " not found"};
    }

    if (parse_cmd_line.count("rsa"))
    {
        libcrypt::rsa_sys_params params = libcrypt::rsa_gen_sys();

        libcrypt::rsa_file_signing(params.mod, params.user.private_key, sign_file);

        sign_file.seekg(std::ios::beg);

        return libcrypt::rsa_check_file_sign(params.mod, params.user.shared_key, sign_file);
    }

    if (parse_cmd_line.count("elgamal"))
    {
        libcrypt::elgamal_sys_params params = libcrypt::elgamal_gen_sys();

        libcrypt::elgamal_file_signing(params.dh_sys_params, params.session_key, params.user.private_key, sign_file);

        sign_file.seekg(std::ios::beg);

        return libcrypt::elgamal_check_file_sign(params.dh_sys_params, params.user.shared_key, sign_file);
    }

    if (parse_cmd_line.count("gost"))
    {
        libcrypt::gost_sys_params params = libcrypt::gost_gen_sys();

        libcrypt::gost_file_signing(
            params.mod, params.elliptic_exp, params.elliptic_coef, params.user.private_key, sign_file);

        sign_file.seekg(std::ios::beg);

        return libcrypt::gost_check_file_sign(
            params.mod, params.elliptic_exp, params.elliptic_coef, params.user.shared_key, sign_file);
    }

    return false;
}

}  // namespace libcrypt