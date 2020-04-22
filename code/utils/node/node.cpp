#include "node.hpp"
#include "../metadata.hpp"
#include "../users/user.hpp"
#include "../encryption/aes_gcm.hpp"

#include "../../flag.h"
#if EMULATING
#  include "../../tests/SGX_Emulator/sgx_trts.hpp"
#else
#   include "sgx_trts.h"
#endif

#include <string>
#include <cstring>
#include <map>

using namespace std;



Node::Node(Node *parent, const string &uuid, const string &relative_path, AES_GCM_context *root_key):Metadata::Metadata(root_key) {
  this->parent = parent;
  this->relative_path = relative_path;
  this->uuid = uuid;

  this->node_entries = new map<string, Node*>();
  this->entitlements = new map<string, unsigned char>();
}
Node::Node(Node *parent, const string &uuid, AES_GCM_context *root_key):Node::Node(parent, uuid, "", root_key) {}

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

  // check entitlements
  for (auto it = this->entitlements->begin(); it != this->entitlements->end(); ++it)
    if (other->entitlements->find(it->first) == other->entitlements->end())
      return false;

  return Metadata::equals(other);
}

string Node::absolute_path() {
  if (this->parent == NULL)
    return this->relative_path;
  else if (this->parent->node_type == SUPERNODE_TYPE)
    return this->parent->absolute_path() + this->relative_path;
  return this->parent->absolute_path() + "/" + this->relative_path;
}



bool Node::is_correct_node(string parent_path) {
  size_t index = parent_path.find('/');
  return parent_path.substr(0, index).compare(this->relative_path) == 0;
}

Node* Node::retrieve_node(string parent_path) {
  if (parent_path.compare(this->relative_path) == 0)
    return this;

  int index = parent_path.find('/');
  string relative_path = parent_path.substr(index+1);

  for (auto it = this->node_entries->begin(); it != this->node_entries->end(); it++) {
    Node *node = it->second;
    if (node->is_correct_node(relative_path))
      return node->retrieve_node(relative_path);
  }
  return NULL;
}

int Node::add_node_entry(Node *node) {
  auto entry = this->node_entries->find(node->uuid);
  if (entry != this->node_entries->end())
    return -1;

  this->node_entries->insert(pair<string, Node*>(node->uuid, node));
  return 0;
}

int Node::link_node_entry(string uuid, Node *node) {
  auto entry = this->node_entries->find(uuid);
  if (entry == this->node_entries->end())
    return -1;

  entry->second = node;
  return 0;
}

int Node::remove_node_entry(Node *node) {
  auto it = this->node_entries->find(node->uuid);
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
  size_t size = sizeof(unsigned char);
  if (this->node_type != FILENODE_TYPE)
    size += sizeof(int) + this->node_entries->size() * Node::UUID_SIZE;
  else
    size += sizeof(int);
  return size;
}

int Node::p_dump_preamble(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->p_preamble_size())
    return -1;

  int written = 0;
  std::memcpy(buffer+written, &this->node_type, sizeof(unsigned char)); written += sizeof(unsigned char);

  if (this->node_type != FILENODE_TYPE) {
    int entries_len = this->node_entries->size();
    std::memcpy(buffer+written, &entries_len, sizeof(int)); written += sizeof(int);
    for (auto it = this->node_entries->begin(); it != this->node_entries->end(); ++it) {
      string uuid = it->first;
      std::memcpy(buffer+written, uuid.c_str(), UUID_SIZE);
      written += UUID_SIZE;
    }
  } else {
    int entries_len = 0;
    std::memcpy(buffer+written, &entries_len, sizeof(int)); written += sizeof(int);
  }

  return written;
}

int Node::p_load_preamble(const size_t buffer_size, const char *buffer) {
  int read = 0;
  std::memcpy(&this->node_type, buffer+read, sizeof(unsigned char)); read += sizeof(unsigned char);

  int entries_len = 0;
  memcpy(&entries_len, buffer+read, sizeof(int)); read += sizeof(int);
  for (int i = 0; i < entries_len; i++) {
    string uuid(UUID_SIZE-1, ' ');
    std::memcpy(const_cast<char*>(uuid.data()), buffer+read, UUID_SIZE);
    read += UUID_SIZE;
    this->node_entries->insert(pair<string, Node*>(uuid, NULL));
  }

  return read;
}


size_t Node::p_sensitive_size() {
  size_t size = sizeof(int) + this->relative_path.length()+1;
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
