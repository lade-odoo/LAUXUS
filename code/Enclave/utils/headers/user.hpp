#ifndef __USER_HPP__
#define __USER_HPP__

#include "../../../flag.h"
#if EMULATING
#   include "../../../tests/SGX_Emulator/sgx_tcrypto.hpp"
#else
#   include "sgx_tcrypto.h"
#endif

#include "uuid.hpp"

#include <string>
#include <map>

using namespace std;


class User {
  public:
    lauxus_uuid_t *u_uuid;
    sgx_ec256_public_t *pk_u;

    User();
    User(const string &name, const sgx_ec256_public_t *pk);
    ~User();

    bool is_root();
    void set_root();
    bool is_auditor();
    void set_auditor();

    bool equals(User *other);

    size_t size();
    int dump(const size_t buffer_size, uint8_t *buffer);
    int load(const size_t buffer_size, const uint8_t *buffer);

  private:
    string name;
};

#endif /*__USER_HPP__*/
