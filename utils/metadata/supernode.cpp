#include "../../utils/metadata/supernode.hpp"
#include "../../utils/metadata/node.hpp"
#include "../../utils/encryption.hpp"

#include "sgx_tcrypto.h"
#include <cerrno>
#include <string>
#include <cstring>
#include <map>


Supernode::Supernode(const std::string &filename, AES_GCM_context *root_key):Node::Node(filename, root_key) {
  this->allowed_users = new std::map<int, std::pair<std::string, sgx_ec256_public_t*>>;
}

Supernode::~Supernode() {
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    std::pair<std::string, sgx_ec256_public_t*> pair = it->second;
    free(pair.second);
  }

  this->allowed_users->clear();
  delete this->allowed_users;
}


int Supernode::create_user(const std::string &username, sgx_ec256_public_t *p_public) {
  if (check_user(username, p_public) >= 0)
    return -1;

  int id = this->allowed_users->size();
  sgx_ec256_public_t *pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
  std::memcpy(pk, p_public, sizeof(sgx_ec256_public_t));
  std::pair<std::string, sgx_ec256_public_t*> pair = std::pair<std::string, sgx_ec256_public_t*>(username, pk);

  this->allowed_users->insert(std::pair<int, std::pair<std::string, sgx_ec256_public_t*>>(id, pair));
  return id;
}

int Supernode::check_user(const std::string &username, sgx_ec256_public_t *p_public) {
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    std::pair<std::string, sgx_ec256_public_t*> pair = it->second;
    if (std::memcmp(p_public, pair.second, sizeof(sgx_ec256_public_t)) == 0 &&
        username.compare(pair.first) == 0)
      return it->first;
  }
  return -1;
}


size_t Supernode::size_sensitive() {
  size_t size = 0;
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    std::pair<std::string, sgx_ec256_public_t*> pair = it->second;
    int username_len = pair.first.length()+1;
    size += 2*sizeof(int) + username_len + sizeof(sgx_ec256_public_t);
  }
  return size;
}

int Supernode::dump_sensitive(char *buffer) {
  size_t written = 0;
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    std::pair<std::string, sgx_ec256_public_t*> pair = it->second;
    int username_len = pair.first.length()+1;

    std::memcpy(buffer+written, &it->first, sizeof(int)); written += sizeof(int);
    std::memcpy(buffer+written, &username_len, sizeof(int)); written += sizeof(int);
    std::memcpy(buffer+written, (char*)pair.first.c_str(), username_len); written += username_len;
    std::memcpy(buffer+written, pair.second, sizeof(sgx_ec256_public_t)); written += sizeof(sgx_ec256_public_t);
  }
  return written;
}

int Supernode::load_sensitive(const size_t buffer_size, const char *buffer) {
  size_t read = 0;
  for (size_t index = 0; read < buffer_size; index++) {
    int id, username_len;
    sgx_ec256_public_t *pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));

    std::memcpy(&id, buffer+read, sizeof(int)); read += sizeof(int);
    std::memcpy(&username_len, buffer+read, sizeof(int)); read += sizeof(int);
    char username[username_len];

    std::memcpy(username, buffer+read, username_len); read += username_len;
    std::memcpy(pk, buffer+read, sizeof(sgx_ec256_public_t)); read += sizeof(sgx_ec256_public_t);

    std::pair<std::string, sgx_ec256_public_t*> pair = std::pair<std::string, sgx_ec256_public_t*>(std::string(username), pk);
    this->allowed_users->insert(std::pair<int, std::pair<std::string, sgx_ec256_public_t*>>(id, pair));
  }
  return read;
}
