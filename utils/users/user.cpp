#include "../../utils/users/user.hpp"
#include "sgx_tcrypto.h"
#include <string>


User::User(const std::string &name, size_t pk_size, sgx_ec256_public_t *pk) {
  this->id = -1;
  this->name = name;
  this->pk_size = pk_size;
  this->pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
  std::memcpy(this->pk, pk, pk_size);
}

User::User() {
  this->id = -1;
  this->name = "";
  this->pk_size = sizeof(sgx_ec256_public_t);
  this->pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
}

User::~User() {
  free(pk);
}


bool User::is_root() {
  return this->id == 0;
}

int User::compare(User *other) {
  return other->name.compare(this->name);
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
  status = sgx_ecdsa_verify(challenge, challenge_size, pk, sig, &result, handle);
  if (status != SGX_SUCCESS || result == SGX_EC_INVALID_SIGNATURE)
    return -1;
  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS)
    return -1;

  return 0;
}


size_t User::dump_size() {
  return 2*sizeof(int) + this->name.length()+1 + this->pk_size;
}

int User::dump(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->dump_size())
    return -1;

  size_t written = 0; int name_len = this->name.length() + 1;
  std::memcpy(buffer, &this->id, sizeof(int)); written += sizeof(int);
  std::memcpy(buffer+written, &name_len, sizeof(int)); written += sizeof(int);
  std::memcpy(buffer+written, (char*)this->name.c_str(), name_len); written += name_len;
  std::memcpy(buffer+written, this->pk, sizeof(sgx_ec256_public_t)); written += sizeof(sgx_ec256_public_t);

  return written;
}

int User::load(const size_t buffer_size, const char *buffer) {
  if (buffer_size < 2*sizeof(int))
    return -1;

  size_t read = 0; int name_len = 0;
  std::memcpy(&this->id, buffer, sizeof(int)); read += sizeof(int);
  std::memcpy(&name_len, buffer+read, sizeof(int)); read += sizeof(int);

  char name_buff[name_len];
  if (buffer_size-read < name_len+sizeof(sgx_ec256_public_t)) // change that
    return -1;

  std::memcpy(name_buff, buffer+read, name_len); read += name_len;
  std::memcpy(this->pk, buffer+read, sizeof(sgx_ec256_public_t)); read += sizeof(sgx_ec256_public_t);

  this->name = std::string(name_buff);
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
