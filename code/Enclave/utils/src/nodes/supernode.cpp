#include "../../headers/nodes/supernode.hpp"


Supernode::Supernode(lauxus_gcm_t *root_key):Node::Node("/", root_key) {
  this->type = LAUXUS_SUPERNODE;
  memcpy(this->n_uuid, "0000-00-00-00-000000", sizeof(lauxus_uuid_t));
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
  size_t size = Node::p_sensitive_size();
  size += sizeof(size_t);
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    User *user = it->second;
    size += user->size();
  }
  return size;
}

int Supernode::p_dump_sensitive(const size_t buffer_size, uint8_t *buffer) {
  if (buffer_size < this->p_sensitive_size())
    return -1;

  int written = Node::p_dump_sensitive(buffer_size, buffer);
  if (written < 0)
    return -1;

  size_t users_len = this->allowed_users->size();
  memcpy(buffer+written, &users_len, sizeof(size_t)); written += sizeof(size_t);
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    User *user = it->second;
    int step = user->dump(buffer_size-written, buffer+written);
    if (step < 0)
      return -1;
    written += step;
  }
  return written;
}

int Supernode::p_load_sensitive(const size_t buffer_size, const uint8_t *buffer) {
  size_t read = Node::p_load_sensitive(buffer_size, buffer);
  if (read < 0)
    return -1;

  size_t users_len = 0;
  memcpy(&users_len, buffer+read, sizeof(size_t)); read += sizeof(size_t);
  for (int i = 0; i < users_len; i++) {
    User *user = new User();
    int step = user->load(buffer_size-read, buffer+read);
    if (step < 0)
      return -1;
    read += step;

    this->allowed_users->insert(pair<string, User*>(string(user->u_uuid->v), user));
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

  this->allowed_users->insert(pair<string, User*>(string(user->u_uuid->v), user));
  return user;
}

User *Supernode::remove_user_from_uuid(const lauxus_uuid_t *u_uuid) {
  User *removed = this->retrieve_user(u_uuid);
  if (removed == NULL || removed->is_root())
    return NULL;

  this->allowed_users->erase(string(removed->u_uuid->v));
  return removed;
}

User *Supernode::check_user(User *user) {
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it)
    if (user->equals(it->second))
      return it->second;

  return NULL;
}

User *Supernode::retrieve_user(const lauxus_uuid_t *u_uuid) {
  auto it = this->allowed_users->find(string(u_uuid->v));
  if (it == this->allowed_users->end())
    return NULL;

  return it->second;
}
