#include "../../headers/nodes/node.hpp"
#include "../../../../flag.h"
#if EMULATING
#   include "../../../../tests/SGX_Emulator/Enclave_t.hpp"
#else
#   include "../../../../Enclave/Enclave_t.h"
#endif


Node::Node(const string &relative_path, lauxus_gcm_t *root_key):Metadata::Metadata(root_key) {
  this->n_uuid = (lauxus_uuid_t*) malloc(sizeof(lauxus_uuid_t)); lauxus_random_uuid(this->n_uuid);
  this->relative_path = relative_path;

  this->node_entries = new map<string, lauxus_uuid_t*>();
  this->entitlements = new map<string, lauxus_right_t>();

  this->update_atime(); this->update_mtime(); this->update_ctime();
}
Node::Node(lauxus_gcm_t *root_key):Node::Node("", root_key) {}

Node::~Node() {
  free(this->n_uuid);
  for (auto it = this->node_entries->begin(); it != this->node_entries->end(); ++it)
    free(it->second);

  delete this->node_entries;
  delete this->entitlements;
}


bool Node::equals(Node *other) {
  if ((this->node_entries->size() != other->node_entries->size()) ||
      (this->entitlements->size() != other->entitlements->size()) ||
      (memcmp(this->n_uuid, other->n_uuid, sizeof(lauxus_uuid_t)) != 0) ||
      (this->relative_path.compare(other->relative_path) != 0))
    return false;

  for (auto it = this->node_entries->begin(); it != this->node_entries->end(); ++it) {
    string path = it->first;
    lauxus_uuid_t *uuid = it->second;
    if (other->node_entries->find(path) == other->node_entries->end() ||
          memcmp(uuid, other->node_entries->find(path)->second, sizeof(lauxus_uuid_t)) != 0)
      return false;
  }

  return Metadata::equals(other);
}


int Node::add_node_entry(string relative_path, lauxus_uuid_t *uuid) {
  auto entry = this->node_entries->find(relative_path);
  if (entry != this->node_entries->end())
    return -1;

  lauxus_uuid_t *stored = (lauxus_uuid_t*) malloc(sizeof(lauxus_uuid_t));
  memcpy(stored, uuid, sizeof(lauxus_uuid_t));
  this->node_entries->insert(pair<string, lauxus_uuid_t*>(relative_path, stored));
  return 0;
}

int Node::remove_node_entry(string relative_path) {
  auto it = this->node_entries->find(relative_path);
  if (it == this->node_entries->end())
    return -1;

  free(it->second);
  this->node_entries->erase(it);
  return 0;
}


bool Node::has_user_rights(const lauxus_right_t min_rights, User *user) {
  if (user->is_root())
    return true;
  else if (this->type == LAUXUS_SUPERNODE) // supernode must be readable by everyone
    return lauxus_has_rights(min_rights, lauxus_read_right());

  auto it = this->entitlements->find(string(user->u_uuid->v));
  if (it == this->entitlements->end())
    return false;
  return lauxus_has_rights(min_rights, it->second);
}

int Node::edit_user_rights(const lauxus_right_t rights, User *user) {
  if (user->is_root() || this->type == LAUXUS_SUPERNODE)
    return -1;

  string str_uuid = string(user->u_uuid->v);
  auto it = this->entitlements->find(str_uuid);
  if (it == this->entitlements->end())
    this->entitlements->insert(pair<string, lauxus_right_t>(str_uuid, rights));
  else
    it->second = rights;
  return 0;
}

int Node::remove_user_rights(User *user) {
  if (user->is_root())
    return -1;

  auto it = this->entitlements->find(string(user->u_uuid->v));
  if (it == this->entitlements->end())
    return 0;

  this->entitlements->erase(it);
  return 0;
}

lauxus_right_t Node::get_rights(User *user) {
  if (user->is_root())
    return lauxus_owner_right();
  if (this->type == LAUXUS_SUPERNODE) // supernode must be readable by everyone
    return lauxus_read_right();

  auto it = this->entitlements->find(string(user->u_uuid->v));
  if (it == this->entitlements->end())
    return lauxus_no_rights();
  return it->second;
}


size_t Node::p_preamble_size() {
  return sizeof(lauxus_node_type) + sizeof(lauxus_uuid_t) + 3*sizeof(time_t);
}

int Node::p_dump_preamble(const size_t buffer_size, uint8_t *buffer) {
  if (buffer_size < this->p_preamble_size())
    return -1;

  size_t written = 0;
  memcpy(buffer, &this->type, sizeof(lauxus_node_type)); written += sizeof(lauxus_node_type);
  memcpy(buffer+written, this->n_uuid, sizeof(lauxus_uuid_t)); written += sizeof(lauxus_uuid_t);
  memcpy(buffer+written, &this->atime, sizeof(time_t)); written += sizeof(time_t);
  memcpy(buffer+written, &this->mtime, sizeof(time_t)); written += sizeof(time_t);
  memcpy(buffer+written, &this->ctime, sizeof(time_t)); written += sizeof(time_t);
  return written;
}

int Node::p_load_preamble(const size_t buffer_size, const uint8_t *buffer) {
  size_t read = 0;

  memcpy(&this->type, buffer, sizeof(lauxus_node_type)); read += sizeof(lauxus_node_type);
  memcpy(this->n_uuid, buffer+read, sizeof(lauxus_uuid_t)); read += sizeof(lauxus_uuid_t);
  memcpy(&this->atime, buffer+read, sizeof(time_t)); read += sizeof(time_t);
  memcpy(&this->mtime, buffer+read, sizeof(time_t)); read += sizeof(time_t);
  memcpy(&this->ctime, buffer+read, sizeof(time_t)); read += sizeof(time_t);

  return read;
}


size_t Node::p_sensitive_size() {
  size_t size = sizeof(size_t) + this->relative_path.length()+1;

  if (this->type != LAUXUS_FILENODE) {
    size += sizeof(size_t);
    for (auto it = this->node_entries->begin(); it != this->node_entries->end(); ++it)
      size += sizeof(lauxus_uuid_t) + sizeof(size_t) + it->first.length()+1;
  }

  size += sizeof(size_t) + this->entitlements->size() * (sizeof(lauxus_uuid_t) + sizeof(lauxus_right_t));
  return size;
}

int Node::p_dump_sensitive(const size_t buffer_size, uint8_t *buffer) {
  if (buffer_size < this->p_sensitive_size())
    return -1;

  size_t written = 0;
  size_t path_len = this->relative_path.length() + 1;
  memcpy(buffer+written, &path_len, sizeof(size_t)); written += sizeof(size_t);
  memcpy(buffer+written, this->relative_path.c_str(), path_len); written += path_len;

  if (this->type != LAUXUS_FILENODE) {
    size_t entries_len = this->node_entries->size();
    memcpy(buffer+written, &entries_len, sizeof(size_t)); written += sizeof(size_t);
    for (auto it = this->node_entries->begin(); it != this->node_entries->end(); ++it) {
      string relative_path = it->first; size_t path_len = relative_path.length()+1;
      lauxus_uuid_t *uuid = it->second;

      memcpy(buffer+written, &path_len, sizeof(size_t)); written += sizeof(size_t);
      memcpy(buffer+written, relative_path.c_str(), path_len); written += path_len;
      memcpy(buffer+written, uuid, sizeof(lauxus_uuid_t)); written += sizeof(lauxus_uuid_t);
    }
  }

  size_t entitlements_len = this->entitlements->size();
  memcpy(buffer+written, &entitlements_len, sizeof(size_t)); written += sizeof(size_t);
  for (auto it = this->entitlements->begin(); it != this->entitlements->end(); ++it) {
    string str_uuid = it->first; lauxus_uuid_t uuid = {0}; memcpy(uuid.v, str_uuid.c_str(), sizeof(lauxus_uuid_t));
    lauxus_right_t rights = it->second;

    memcpy(buffer+written, &uuid, sizeof(lauxus_uuid_t)); written += sizeof(lauxus_uuid_t);
    memcpy(buffer+written, &rights, sizeof(lauxus_right_t)); written += sizeof(lauxus_right_t);
  }

  return written;
}

int Node::p_load_sensitive(const size_t buffer_size, const uint8_t *buffer) {
  if (buffer_size < sizeof(size_t))
    return -1;

  size_t read = 0; size_t path_len = 0;
  memcpy(&path_len, buffer+read, sizeof(size_t)); read += sizeof(size_t);
  if (buffer_size-read < path_len)
    return -1;

  this->relative_path.resize(path_len-1);
  memcpy(const_cast<char*>(this->relative_path.data()), buffer+read, path_len); read += path_len;

  if (this->type != LAUXUS_FILENODE) {
    size_t entries_len = 0;
    memcpy(&entries_len, buffer+read, sizeof(size_t)); read += sizeof(size_t);
    for (int i = 0; i < entries_len; i++) {
      int path_len = 0; string relative_path="";
      lauxus_uuid_t *uuid = (lauxus_uuid_t*) malloc(sizeof(lauxus_uuid_t));

      memcpy(&path_len, buffer+read, sizeof(size_t)); read += sizeof(size_t);
      relative_path.resize(path_len - 1);
      memcpy(const_cast<char*>(relative_path.data()), buffer+read, path_len); read += path_len;
      memcpy(uuid, buffer+read, sizeof(lauxus_uuid_t)); read += sizeof(lauxus_uuid_t);
      this->node_entries->insert(pair<string, lauxus_uuid_t*>(relative_path, uuid));
    }
  }

  size_t entitlements_len = 0;
  memcpy(&entitlements_len, buffer+read, sizeof(size_t)); read += sizeof(size_t);
  for (int i = 0; i < entitlements_len; i++) {
    lauxus_uuid_t uuid = {0};
    lauxus_right_t rights = {0};

    memcpy(&uuid, buffer+read, sizeof(lauxus_uuid_t)); read += sizeof(lauxus_uuid_t);
    memcpy(&rights, buffer+read, sizeof(lauxus_right_t)); read += sizeof(lauxus_right_t);

    this->entitlements->insert(pair<string, lauxus_right_t>(string(uuid.v), rights));
  }

  return read;
}


int Node::update_atime() { update_time(&(this->atime)); }
int Node::update_mtime() { update_time(&(this->mtime)); }
int Node::update_ctime() { update_time(&(this->ctime)); }
int Node::update_time(time_t *time) {
  int ret;
  if (ocall_get_current_time(&ret, time) != SGX_SUCCESS)
    return -1;
  return 0;
}
