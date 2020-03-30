#include "../../utils/metadata/supernode.hpp"
#include "../../utils/metadata/node.hpp"
#include "../../utils/users/user.hpp"
#include "../../utils/encryption.hpp"

#include "sgx_tcrypto.h"
#include <cerrno>
#include <string>
#include <cstring>
#include <map>


Supernode::Supernode(const std::string &filename, AES_GCM_context *root_key):Node::Node(filename, root_key) {
  this->allowed_users = new std::map<int, User*>();
}

Supernode::~Supernode() {
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    User *user = it->second;
    delete(user);
  }

  this->allowed_users->clear();
  delete this->allowed_users;
}


User *Supernode::root_user() {
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    User *current = it->second;
    if (current->is_root())
      return current;
  }
  return NULL;
}


User *Supernode::add_user(User *user) {
  if (check_user(user) != NULL)
    return NULL;

  int id = this->allowed_users->size();
  user->id = id;
  this->allowed_users->insert(std::pair<int, User*>(id, user));
  return user;
}

User *Supernode::check_user(User *user) {
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    User *current = it->second;
    if (user->compare(current) == 0)
      return current;
  }
  return NULL;
}

User *Supernode::retrieve_user(int user_id) {
  auto it = this->allowed_users->find(user_id);
  if (it == this->allowed_users->end())
    return NULL;

  return it->second;
}


size_t Supernode::size_sensitive() {
  size_t size = 0;
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    User *user = it->second;
    size += user->dump_size();
  }
  return size;
}

int Supernode::dump_sensitive(const size_t buffer_size, char *buffer) {
  size_t written = 0;
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    User *user = it->second;
    size_t step = user->dump(buffer_size-written, buffer+written);
    if (step < 0)
      return -1;
    written += step;
  }
  return written;
}

int Supernode::load_sensitive(Node *parent, const size_t buffer_size, const char *buffer) {
  size_t read = 0;
  for (size_t index = 0; read < buffer_size; index++) {
    User *user = new User();
    size_t step = user->load(buffer_size-read, buffer+read);
    if (step < 0)
      return -1;
    read += step;

    this->allowed_users->insert(std::pair<int, User*>(user->id, user));
  }
  return read;
}
