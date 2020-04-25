#include "filesystem.hpp"
#include "../node/node.hpp"
#include "../node/filenode.hpp"
#include "../node/filenode_content.hpp"
#include "../node/dirnode.hpp"
#include "../node/node_audit.hpp"

#include "../../flag.h"
#if EMULATING
#  include "../tests/SGX_Emulator/Enclave_t.hpp"
#  include "../tests/SGX_Emulator/sgx_error.hpp"
#else
#  include "../Enclave/Enclave_t.h"
#  include "sgx_error.h"
#endif

#include <cerrno>
#include <cstring>
#include <string>

using namespace std;



Node *FileSystem::load_metadata(string uuid) {
  char *buffer = NULL;
  int buffer_size = e_load_meta_from_disk(uuid, &buffer);
  if (buffer_size < 0)
    return NULL;

  unsigned char node_type = 0;
  memcpy(&node_type, buffer, sizeof(unsigned char));

  Node *node;
  if (node_type == Node::FILENODE_TYPE)
    node = new Filenode(uuid, this->root_key, this->block_size);
  else if (node_type == Node::DIRNODE_TYPE)
    node = new Dirnode(uuid, this->root_key);
  else
    return NULL;

  if (node->e_load(buffer_size, buffer) < 0)
    return NULL;

  free(buffer);
  return node;
}

int FileSystem::load_content(Filenode *node, const long offset, const size_t length) {
  map<string, size_t> block_required = FilenodeContent::block_required(this->block_size, offset, length);

  char *buffer = NULL;
  int buffer_size = e_load_fileblocks_from_disk(node->uuid, block_required["start_block"], block_required["end_block"], &buffer);
  if (buffer_size < 0)
    return -1;

  if (node->content->e_load(offset, length, buffer_size, buffer) < 0)
    return -1;
  free(buffer);
  return 0;
}


int FileSystem::e_write_meta_to_disk(Node *node) {
  // dump and encrypt metadata content
  size_t e_size = node->e_size(); char cypher[e_size];
  if (node->e_dump(e_size, cypher) < 0)
    return -EPROTO;

  // save metadata content
  int ret;
  if (ocall_dump_in_dir(&ret, (char*)this->META_DIR.c_str(), (char*)node->uuid.c_str(), e_size, cypher) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  return e_size;
}

int FileSystem::e_write_file_to_disk(Filenode *node, const long up_offset, const size_t up_size) {
  // dump and encrypt metadata content
  size_t e_size = node->content->e_size(up_offset, up_size); char cypher[e_size];
  int offset = node->content->e_dump(up_offset, up_size, e_size, cypher);
  if (offset < 0)
    return -EPROTO;

  // save metadata content
  int ret;
  if (ocall_dump_with_offset_in_dir(&ret, (char*)this->CONTENT_DIR.c_str(), (char*)node->uuid.c_str(), offset, e_size, cypher) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  return e_size;
}

int FileSystem::e_append_audit_to_disk(Node *node, const string &reason) {
  // dump and encrypt metadata content
  size_t e_size = NodeAudit::e_reason_size(reason);
  char cypher[e_size];
  if (NodeAudit::e_reason_dump(this->audit_root_key, reason, e_size, cypher) < 0)
    return -EPROTO;

  // save metadata content
  int ret;
  if (ocall_dump_append_in_dir(&ret, (char*)this->AUDIT_DIR.c_str(), (char*)node->uuid.c_str(), e_size, cypher) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  return e_size;
}


int FileSystem::e_load_meta_from_disk(const string &uuid, char **buffer) {
  int ret = 0;
  if (ocall_file_size(&ret, (char*)this->META_DIR.c_str(), (char*)uuid.c_str()) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  size_t buffer_size = ret;
  *buffer = new char[buffer_size];
  if (ocall_load_file(&ret, (char*)this->META_DIR.c_str(), (char*)uuid.c_str(), 0, buffer_size, *buffer) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  return ret;
}

int FileSystem::e_load_fileblocks_from_disk(const string &uuid, const size_t start_block, const size_t end_block, char **buffer) {
  int ret = 0;
  if (ocall_file_size(&ret, (char*)this->CONTENT_DIR.c_str(), (char*)uuid.c_str()) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  size_t file_size = ret;
  size_t offset = start_block * this->block_size;
  size_t length = (end_block - start_block + 1) * this->block_size;
  if (offset > file_size)
    return -EPROTO;
  if (offset + length > file_size)
    length = file_size - offset;

  if (length == 0)
    return 0;
  *buffer = new char[length];
  if (ocall_load_file(&ret, (char*)this->CONTENT_DIR.c_str(), (char*)uuid.c_str(), offset, length, *buffer) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  return ret;
}


int FileSystem::delete_from_disk(Node *node, const string &from_dir) {
  int ret;
  if (ocall_delete_from_dir(&ret, (char*)from_dir.c_str(), (char*)node->uuid.c_str()) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  return 0;
}
