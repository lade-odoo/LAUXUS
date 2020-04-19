#include "../../utils/users/user.hpp"

#include "../flag.h"
#if EMULATING
#   include "../../tests/SGX_Emulator/sgx_tcrypto.hpp"
#   include "../../tests/SGX_Emulator/sgx_trts.hpp"
#else
#   include "sgx_tcrypto.h"
#   include "sgx_trts.h"
#endif

#include <string>
#include <cstring>

using namespace std;



User::User(const string &name, size_t pk_size, sgx_ec256_public_t *pk) {
  this->uuid = User::generate_uuid();
  this->name = name;
  this->pk_size = pk_size;
  this->pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
  memcpy(this->pk, pk, pk_size);
}

User::User() {
  this->uuid = User::generate_uuid();
  this->name = "";
  this->pk_size = sizeof(sgx_ec256_public_t);
  this->pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
}

User::~User() {
  free(pk);
}


bool User::is_root() {
  return this->uuid.compare("0000-00-00-00-000000") == 0;
}

void User::set_root() {
  this->uuid = "0000-00-00-00-000000";
}

bool User::equals(User *other) {
  return other->name.compare(this->name) == 0 && other->uuid.compare(this->uuid) == 0 &&
      memcmp(this->pk, other->pk, this->pk_size) == 0;
}



int User::validate_signature(const size_t challenge_size, const uint8_t *challenge,
                            const size_t sig_size, sgx_ec256_signature_t *sig) {
  if (sig_size != sizeof(sgx_ec256_signature_t))
    return -1;

  sgx_ecc_state_handle_t handle;
  uint8_t result;

  sgx_status_t status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS)
    return -1;
  status = sgx_ecdsa_verify(challenge, challenge_size, this->pk, sig, &result, handle);
  if (status != SGX_SUCCESS || result == SGX_EC_INVALID_SIGNATURE)
    return -1;
  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS)
    return -1;

  return 0;
}


size_t User::size() {
  return UUID_SIZE + sizeof(int) + this->name.length()+1 + this->pk_size;
}

int User::dump(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->size())
    return -1;

  size_t written = 0; int name_len = this->name.length() + 1;
  memcpy(buffer+written, this->uuid.c_str(), UUID_SIZE); written += UUID_SIZE;
  memcpy(buffer+written, &name_len, sizeof(int)); written += sizeof(int);
  memcpy(buffer+written, this->name.c_str(), name_len); written += name_len;
  memcpy(buffer+written, this->pk, sizeof(sgx_ec256_public_t)); written += sizeof(sgx_ec256_public_t);

  return written;
}

int User::load(const size_t buffer_size, const char *buffer) {
  if (buffer_size < 2*sizeof(int))
    return -1;

  size_t read = 0; int name_len = 0;
  memcpy(const_cast<char*>(this->uuid.data()), buffer+read, UUID_SIZE); read+= UUID_SIZE;
  memcpy(&name_len, buffer+read, sizeof(int)); read += sizeof(int);

  if (buffer_size-read < name_len+sizeof(sgx_ec256_public_t)) // change that
    return -1;

  this->name.resize(name_len-1);
  memcpy(const_cast<char*>(this->name.data()), buffer+read, name_len); read += name_len;
  memcpy(this->pk, buffer+read, sizeof(sgx_ec256_public_t)); read += sizeof(sgx_ec256_public_t);

  return read;
}


// Static  functions
int User::generate_keys(const size_t pk_size, sgx_ec256_public_t *pk,
                        const size_t sk_size, sgx_ec256_private_t *sk) {
  if (pk_size < sizeof(sgx_ec256_public_t) || sk_size < sizeof(sgx_ec256_private_t))
    return -1;

  sgx_ecc_state_handle_t handle;
  sgx_status_t status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS)
    return -1;
  status = sgx_ecc256_create_key_pair(sk, pk, handle);
  if (status != SGX_SUCCESS)
    return -1;
  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS)
    return -1;

  return 0;
}

int User::sign(const size_t challenge_size, const uint8_t *challenge,
                const size_t sk_size, sgx_ec256_private_t *sk,
                const size_t sig_size, sgx_ec256_signature_t *sig) {
  if (sig_size < sizeof(sgx_ec256_signature_t) || sk_size < sizeof(sgx_ec256_private_t))
    return -1;

  sgx_ecc_state_handle_t handle;
  sgx_status_t status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS)
    return -1;
  status = sgx_ecdsa_sign(challenge, challenge_size, sk, sig, handle);
  if (status != SGX_SUCCESS)
    return -1;
  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS)
    return -1;

  return 0;
}

string User::generate_uuid() {
  const char possibilities[] = "0123456789abcdef";
  const bool dash[] = { 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0 };

  uint8_t indexes[16] = {0};
  sgx_read_rand(indexes, 16);

  string res;
  for (int i = 0; i < 16; i++) {
      if (dash[i]) res += "-";
      res += possibilities[indexes[i] % 16];
  }

  return res;
}
