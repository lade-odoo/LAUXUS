#ifndef __USER_HPP__
#define __USER_HPP__

#include "../flag.h"
#if EMULATING
#  include "../tests/SGX_Emulator/sgx_tcrypto.hpp"
#else
#   include "sgx_tcrypto.h"
#endif

#include <string>
#include <map>


class User {
  public:
    int id;

    User();
    explicit User(const std::string &name, size_t pk_size, sgx_ec256_public_t *pk);
    ~User();

    bool is_root();
    bool equals(User *other);

    int validate_signature(const size_t challenge_size, const uint8_t *challenge,
                          const size_t sig_size, sgx_ec256_signature_t *sig);

    size_t size();
    int dump(const size_t buffer_size, char *buffer);
    int load(const size_t buffer_size, const char *buffer);


    // Static functions
    static int generate_keys(const size_t pk_size, sgx_ec256_public_t *pk,
                            const size_t sk_size, sgx_ec256_private_t *sk);
    static int sign(const size_t challenge_size, const uint8_t *challenge,
                    const size_t sk_size, sgx_ec256_private_t *sk,
                    const size_t sig_size, sgx_ec256_signature_t *sig);

  private:
    std::string name;
    size_t pk_size;
    sgx_ec256_public_t *pk;
};

#endif /*__USER_HPP__*/
