#include "../../utils/metadata/supernode.hpp"
#include "../../utils/metadata/node.hpp"
#include "../../utils/encryption.hpp"

#include "sgx_tcrypto.h"
#include <cerrno>
#include <string>
#include <cstring>
#include <map>



Supernode::Supernode(const std::string &filename, AES_GCM_context *root_key):Node::Node(filename, root_key) {
  this->allowed_users = new std::map<int, sgx_ec256_public_t*>;
}

Supernode::~Supernode() {
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it)
    free(it->second);

  this->allowed_users->clear();
  delete this->allowed_users;
}


int Supernode::create_user(sgx_ec256_public_t *p_public) {
  if (check_user(p_public) >= 0)
    return -1;

  int id = this->allowed_users->size();
  sgx_ec256_public_t *pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
  std::memcpy(pk, p_public, sizeof(sgx_ec256_public_t));
  this->allowed_users->insert(std::pair<int, sgx_ec256_public_t*>(id, pk));
  return id;
}

int Supernode::check_user(sgx_ec256_public_t *p_public) {
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    if (std::memcmp(p_public, it->second, sizeof(sgx_ec256_public_t)) == 0)
      return it->first;
  }
  return -1;
}


size_t Supernode::size_sensitive() {
  return (sizeof(int) + sizeof(sgx_ec256_public_t)) * this->allowed_users->size();
}

int Supernode::dump_sensitive(char *buffer) {
  size_t written = 0;
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    std::memcpy(buffer+written, &it->first, sizeof(int)); written += sizeof(int);
    std::memcpy(buffer+written, it->second, sizeof(sgx_ec256_public_t)); written += sizeof(sgx_ec256_public_t);
  }
  return written;
}

int Supernode::load_sensitive(const size_t buffer_size, const char *buffer) {
  size_t read = 0, size_entry = sizeof(int)+sizeof(sgx_ec256_public_t);
  for (size_t index = 0; read+size_entry <= buffer_size; index++) {
    int id; sgx_ec256_public_t *pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
    std::memcpy(&id, buffer+read, sizeof(int)); read += sizeof(int);
    std::memcpy(pk, buffer+read, sizeof(sgx_ec256_public_t)); read += sizeof(sgx_ec256_public_t);

    this->allowed_users->insert(std::pair<int, sgx_ec256_public_t*>(id, pk));
    read += size_entry;
  }
  return read;
}
