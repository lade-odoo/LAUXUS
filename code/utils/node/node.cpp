#include "node.hpp"
#include "../metadata.hpp"
#include "../users/user.hpp"
#include "../encryption/aes_gcm.hpp"

#include "../../flag.h"
#if EMULATING
#  include "../../tests/SGX_Emulator/Enclave_t.hpp"
#  include "../../tests/SGX_Emulator/sgx_trts.hpp"
#else
#   include "../../Enclave/Enclave_t.h"
#   include "sgx_trts.h"
#endif

#include <string>
#include <cstring>
#include <map>

using namespace std;



Node::Node(const string &uuid, const string &relative_path, AES_GCM_context *root_key):Metadata::Metadata(root_key) {
  this->relative_path = relative_path;
  this->uuid = uuid;

  this->node_entries = new map<string, string>();
  this->entitlements = new map<string, unsigned char>();

  this->update_atime(); this->update_mtime(); this->update_ctime();
}
Node::Node(const string &uuid, AES_GCM_context *root_key):Node::Node(uuid, "", root_key) {}

Node::~Node() {
  delete this->node_entries;
  delete this->entitlements;
}


bool Node::equals(Node *other) {
  if (this->node_entries->size() != other->node_entries->size())
    return false;
  if (this->entitlements->size() != other->entitlements->size())
    return false;
  if (this->uuid.compare(other->uuid) != 0 || this->relative_path.compare(other->relative_path) !=0)
    return false;

  // check children entries
  for (auto it = this->node_entries->begin(); it != this->node_entries->end(); ++it)
    if (other->node_entries->find(it->first) == other->node_entries->end())
      return false;
    else if (other->node_entries->find(it->first)->second != it->second)
      return false;

  // check entitlements
  for (auto it = this->entitlements->begin(); it != this->entitlements->end(); ++it)
    if (other->entitlements->find(it->first) == other->entitlements->end())
      return false;

  return Metadata::equals(other);
}


int Node::add_node_entry(string relative_path, string uuid) {
  auto entry = this->node_entries->find(relative_path);
  if (entry != this->node_entries->end())
    return -1;

  this->node_entries->insert(pair<string, string>(relative_path, uuid));
  return 0;
}

int Node::remove_node_entry(string relative_path) {
  auto it = this->node_entries->find(relative_path);
  if (it == this->node_entries->end())
    return -1;

  this->node_entries->erase(it);
  return 0;
}


bool Node::has_user_rights(const unsigned char min_rights, User *user) {
  if (user->is_root())
    return true;

  if (this->node_type == SUPERNODE_TYPE) // supernode must be readable by everyone
    return min_rights == (min_rights & (READ_RIGHT | EXEC_RIGHT));

  auto it = this->entitlements->find(user->uuid);
  if (it == this->entitlements->end())
    return false;
  if (it->second == OWNER_RIGHT)
    return true;
  return min_rights == (min_rights & it->second);
}

int Node::edit_user_entitlement(const unsigned char rights, User *user) {
  if (user->is_root() || this->node_type == SUPERNODE_TYPE)
    return -1;

  auto it = this->entitlements->find(user->uuid);
  if (it == this->entitlements->end()) {
    this->entitlements->insert(std::pair<string, unsigned char>(user->uuid, rights));
    return 0;
  }

  it->second = rights;
  return 0;
}

int Node::remove_user_entitlement(User *user) {
  if (user->is_root())
    return -1;

  auto it = this->entitlements->find(user->uuid);
  if (it == this->entitlements->end())
    return 0;

  this->entitlements->erase(it);
  return 0;
}

int Node::get_rights(User *user) {
  if (user->is_root())
    return READ_RIGHT | WRITE_RIGHT | EXEC_RIGHT;
  if (this->node_type == SUPERNODE_TYPE) // supernode must be readable by everyone
    return READ_RIGHT | EXEC_RIGHT;

  auto it = this->entitlements->find(user->uuid);
  if (it == this->entitlements->end())
    return 0;

  if (it->second == OWNER_RIGHT)
    return READ_RIGHT | WRITE_RIGHT | EXEC_RIGHT;
  return it->second;
}


size_t Node::p_preamble_size() {
  return sizeof(unsigned char) + 3*sizeof(time_t);
}

int Node::p_dump_preamble(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->p_preamble_size())
    return -1;

  int written = 0;
  std::memcpy(buffer, &this->node_type, sizeof(unsigned char)); written += sizeof(unsigned char);
  std::memcpy(buffer+written, &(this->atime), sizeof(time_t)); written += sizeof(time_t);
  std::memcpy(buffer+written, &(this->mtime), sizeof(time_t)); written += sizeof(time_t);
  std::memcpy(buffer+written, &(this->ctime), sizeof(time_t)); written += sizeof(time_t);
  return written;
}

int Node::p_load_preamble(const size_t buffer_size, const char *buffer) {
  int read = 0;

  std::memcpy(&this->node_type, buffer, sizeof(unsigned char)); read += sizeof(unsigned char);
  std::memcpy(&(this->atime), buffer+read, sizeof(time_t)); read += sizeof(time_t);
  std::memcpy(&(this->mtime), buffer+read, sizeof(time_t)); read += sizeof(time_t);
  std::memcpy(&(this->ctime), buffer+read, sizeof(time_t)); read += sizeof(time_t);

  return read;
}


size_t Node::p_sensitive_size() {
  size_t size = sizeof(int) + this->relative_path.length()+1;

  if (this->node_type != FILENODE_TYPE) {
    size += sizeof(int);
    for (auto it = this->node_entries->begin(); it != this->node_entries->end(); ++it)
      size += UUID_SIZE + sizeof(int) + it->first.length()+1;
  }

  size += sizeof(int) + this->entitlements->size() * (UUID_SIZE + sizeof(unsigned char));
  return size;
}

int Node::p_dump_sensitive(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->p_sensitive_size())
    return -1;

  size_t written = 0;
  int path_len = this->relative_path.length() + 1;
  memcpy(buffer+written, &path_len, sizeof(int)); written += sizeof(int);
  memcpy(buffer+written, this->relative_path.c_str(), path_len); written += path_len;

  if (this->node_type != FILENODE_TYPE) {
    int entries_len = this->node_entries->size();
    memcpy(buffer+written, &entries_len, sizeof(int)); written += sizeof(int);
    for (auto it = this->node_entries->begin(); it != this->node_entries->end(); ++it) {
      string relative_path = it->first; int path_len = relative_path.length()+1;
      string uuid = it->second;

      memcpy(buffer+written, &path_len, sizeof(int)); written += sizeof(int);
      memcpy(buffer+written, relative_path.c_str(), path_len); written += path_len;
      memcpy(buffer+written, uuid.c_str(), UUID_SIZE); written += UUID_SIZE;
    }
  }

  int entitlements_len = this->entitlements->size();
  memcpy(buffer+written, &entitlements_len, sizeof(int)); written += sizeof(int);
  for (auto it = this->entitlements->begin(); it != this->entitlements->end(); ++it) {
    string uuid = it->first;
    unsigned char rights = it->second;

    memcpy(buffer+written, uuid.c_str(), UUID_SIZE); written += UUID_SIZE;
    memcpy(buffer+written, &rights, sizeof(unsigned char)); written += sizeof(unsigned char);
  }

  return written;
}

int Node::p_load_sensitive(const size_t buffer_size, const char *buffer) {
  if (buffer_size < sizeof(int))
    return -1;

  size_t read = 0;
  int path_len = 0;
  memcpy(&path_len, buffer+read, sizeof(int)); read += sizeof(int);
  if ((int)(buffer_size-read) < path_len)
    return -1;

  this->relative_path.resize(path_len-1);
  memcpy(const_cast<char*>(this->relative_path.data()), buffer+read, path_len); read += path_len;

  if (this->node_type != FILENODE_TYPE) {
    int entries_len = 0;
    memcpy(&entries_len, buffer+read, sizeof(int)); read += sizeof(int);
    for (int i = 0; i < entries_len; i++) {
      int path_len = 0; string relative_path="", uuid(UUID_SIZE-1, ' ');

      memcpy(&path_len, buffer+read, sizeof(int)); read += sizeof(int);
      relative_path.resize(path_len - 1);
      memcpy(const_cast<char*>(relative_path.data()), buffer+read, path_len); read += path_len;
      memcpy(const_cast<char*>(uuid.data()), buffer+read, UUID_SIZE); read += UUID_SIZE;
      this->node_entries->insert(pair<string, string>(relative_path, uuid));
    }
  }

  int entitlements_len = 0;
  memcpy(&entitlements_len, buffer+read, sizeof(int)); read += sizeof(int);
  for (int i = 0; i < entitlements_len; i++) {
    string uuid(UUID_SIZE-1, ' ');
    unsigned char rights = 0;

    memcpy(const_cast<char*>(uuid.data()), buffer+read, UUID_SIZE); read += UUID_SIZE;
    memcpy(&rights, buffer+read, sizeof(unsigned char)); read += sizeof(unsigned char);

    this->entitlements->insert(std::pair<string, unsigned char>(uuid, rights));
  }

  return read;
}


int Node::update_atime() { update_time(&(this->atime)); }
int Node::update_mtime() { update_time(&(this->mtime)); }
int Node::update_ctime() { update_time(&(this->ctime)); }
int Node::update_time(time_t *time) {
  int ret;
  if (ocall_get_current_time(&ret, sizeof(time_t), (char*)time) != SGX_SUCCESS || ret < 0)
    return -1;
  return 0;
}


// Static functions
string Node::generate_uuid() {
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
