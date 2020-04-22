#include "supernode.hpp"
#include "node.hpp"
#include "../users/user.hpp"
#include "../encryption/aes_gcm.hpp"

#include <string>
#include <cstring>
#include <map>

using namespace std;


Supernode::Supernode(const string &filename, AES_GCM_context *root_key):Node::Node(NULL, filename, "/", root_key) {
  this->node_type = Node::SUPERNODE_TYPE;
  this->allowed_users = new map<string, User*>();
}

Supernode::~Supernode() {
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    User *user = it->second;
    delete user;
  }

  this->allowed_users->clear();
  delete this->allowed_users;
}


bool Supernode::equals(Supernode *other) {
  if (this->allowed_users->size() != other->allowed_users->size())
    return false;

  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it)
    if (other->check_user(it->second) == NULL)
      return false;

  return Node::equals(other);
}


size_t Supernode::p_sensitive_size() {
  size_t size = sizeof(int);
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    User *user = it->second;
    size += user->size();
  }
  return size;
}

int Supernode::p_dump_sensitive(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->p_sensitive_size())
    return -1;

  size_t written = 0;
  int users_len = this->allowed_users->size();
  memcpy(buffer, &users_len, sizeof(int)); written += sizeof(int);

  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    User *user = it->second;
    int step = user->dump(buffer_size-written, buffer+written);
    if (step < 0)
      return -1;
    written += step;
  }
  return written;
}

int Supernode::p_load_sensitive(const size_t buffer_size, const char *buffer) {
  size_t read = 0;
  int users_len = 0;

  memcpy(&users_len, buffer, sizeof(int)); read += sizeof(int);
  for (int i = 0; i < users_len; i++) {
    User *user = new User();
    int step = user->load(buffer_size-read, buffer+read);
    if (step < 0)
      return -1;
    read += step;

    this->allowed_users->insert(pair<string, User*>(user->uuid, user));
  }
  return read;
}


User *Supernode::add_user(User *user) {
  if (check_user(user) != NULL)
    return NULL;

  if (this->allowed_users->size() == 0)
    user->set_root();
  if (this->allowed_users->size() == 1)
    user->set_auditor();

  this->allowed_users->insert(pair<string, User*>(user->uuid, user));
  return user;
}

User *Supernode::remove_user_from_uuid(string user_uuid) {
  User *removed = this->retrieve_user(user_uuid);
  if (removed == NULL || removed->is_root())
    return NULL;

  this->allowed_users->erase(removed->uuid);
  return removed;
}

User *Supernode::check_user(User *user) {
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it)
    if (user->equals(it->second))
      return it->second;

  return NULL;
}

User *Supernode::retrieve_user(string user_uuid) {
  auto it = this->allowed_users->find(user_uuid);
  if (it == this->allowed_users->end())
    return NULL;

  return it->second;
}
