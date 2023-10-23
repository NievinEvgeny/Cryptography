#pragma once
#include <fstream>

namespace libcrypt {

void rsa_file_signing(int64_t mod, int64_t send_private_key, std::fstream& file);

bool rsa_check_file_sign(int64_t mod, int64_t send_shared_key, std::fstream& file);

}  // namespace libcrypt