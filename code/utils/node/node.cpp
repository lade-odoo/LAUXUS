#include "node.hpp"
#include "../metadata.hpp"
#include "../encryption/aes_gcm.hpp"

#include "../../flag.h"
#if EMULATING
#  include "../../tests/SGX_Emulator/sgx_trts.hpp"
#else
#   include "sgx_trts.h"
#endif

#include <string>
#include <cstring>
#include <iostream>

using namespace std;



Node::Node(const string &uuid, const string &path, AES_GCM_context *root_key):Metadata::Metadata(root_key) {
  this->path = path;
  this->uuid = uuid;
}
Node::Node(const string &uuid, AES_GCM_context *root_key):Node::Node(uuid, "", root_key) {}

Node::~Node() {
}


bool Node::equals(Node *other) {
  if (this->uuid.compare(other->uuid) != 0 || this->path.compare(other->path) !=0)
    return false;

  return Metadata::equals(other);
}


size_t Node::p_sensitive_size() {
  return sizeof(int) + this->path.length()+1;
}

int Node::p_dump_sensitive(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->p_sensitive_size())
    return -1;

  size_t written = 0;
  int path_len = this->path.length() + 1;
  memcpy(buffer+written, &path_len, sizeof(int)); written += sizeof(int);
  memcpy(buffer+written, this->path.c_str(), path_len); written += path_len;

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

  this->path.resize(path_len-1);
  memcpy(const_cast<char*>(this->path.data()), buffer+read, path_len); read += path_len;

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
