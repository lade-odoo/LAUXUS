#include "../utils/filesystem.hpp"
#include "../utils/encryption/aes_gcm.hpp"
#include "../utils/node/node.hpp"
#include "../utils/node/filenode.hpp"
#include "../utils/node/supernode.hpp"
#include "../utils/node/node_audit.hpp"

#include "../flag.h"
#if EMULATING
#  include "../tests/SGX_Emulator/Enclave_t.hpp"
#  include "../tests/SGX_Emulator/sgx_error.hpp"
#else
#  include "../Enclave/Enclave_t.h"
#  include "sgx_error.h"
#endif

#include <cerrno>
#include <string>
#include <vector>

using namespace std;

// ... FREE CONTENT WHEN CD ?


FileSystem::FileSystem(AES_GCM_context *root_key, AES_GCM_context *audit_root_key,
                        Supernode *supernode, size_t block_size=FileSystem::DEFAULT_BLOCK_SIZE) {
  this->root_key = root_key;
  this->audit_root_key = audit_root_key;
  this->supernode = supernode;
  this->block_size = block_size;
  this->current_user = NULL;

  this->load_metadata(supernode);
  this->load_content(supernode);
}

void FileSystem::init_dumping_folders(const string &CONTENT_DIR, const string &META_DIR, const string &AUDIT_DIR) {
  this->CONTENT_DIR = CONTENT_DIR;
  this->META_DIR = META_DIR;
  this->AUDIT_DIR = AUDIT_DIR;
}


int FileSystem::edit_user_entitlement(const string &path, const unsigned char rights, const int user_id) {
  Node *node = this->supernode->retrieve_node(path);
  User *user = this->supernode->retrieve_user(user_id);
  if (node == NULL || user == NULL)
    return -ENOENT;
  if (!node->has_user_rights(Node::OWNER_RIGHT, this->current_user))
    return -EACCES;

  int ret = node->edit_user_entitlement(rights, user);
  if (ret < 0)
    return ret;

  if (e_write_meta_to_disk(node) < 0)
    return -EPROTO;

  return ret;
}


vector<string> FileSystem::readdir() {
  vector<string> entries;

  for (auto itr = this->supernode->node_entries->begin(); itr != this->supernode->node_entries->end(); itr++) {
    Node *children = itr->second;
    if (children->get_rights(this->current_user) > 0)
      entries.push_back(children->relative_path);
  }

  return entries;
}

int FileSystem::get_rights(const string &path) {
  Node *node = this->supernode->retrieve_node(path);
  if (node == NULL)
    return -ENOENT;
  return node->get_rights(this->current_user);
}

int FileSystem::entry_type(const string &path) {
  Node *node = this->supernode->retrieve_node(path);
  if (node == NULL)
    return -ENOENT;
  else if (node->node_type == Node::SUPERNODE_TYPE)
    return EISDIR;
  return EEXIST;
}


int FileSystem::file_size(const string &filepath) {
  Filenode *node = dynamic_cast<Filenode*>(this->supernode->retrieve_node(filepath));
  if (node == NULL)
    return -ENOENT;
  return node->file_size();
}

int FileSystem::create_file(const string &reason, const string &filepath) {
  Node *node = this->supernode->retrieve_node(filepath);
  if (node != NULL)
    return -EEXIST;

  // relative path of the file
  string parent_path = filepath.substr(0, filepath.find_last_of("/") + 1);
  string relative_path = filepath.substr(filepath.find_last_of("/") + 1);

  // create node
  string uuid = Node::generate_uuid();
  Filenode *filenode = new Filenode(uuid, relative_path, this->root_key, this->block_size);
  filenode->edit_user_entitlement(Node::OWNER_RIGHT, this->current_user);

  Node *parent = this->supernode->retrieve_node(parent_path);
  parent->add_node_entry(filenode);

  if (e_append_audit_to_disk(filenode, reason) < 0)
    return -EPROTO;
  if (e_write_meta_to_disk(filenode) < 0)
    return -EPROTO;

  return 0;
}

int FileSystem::read_file(const string &reason, const string &filepath, const long offset, const size_t buffer_size, char *buffer) {
  Filenode *node = dynamic_cast<Filenode*>(this->supernode->retrieve_node(filepath));
  if (node == NULL)
    return -ENOENT;
  if (!node->has_user_rights(Node::READ_RIGHT, this->current_user))
    return -EACCES;

  if (e_append_audit_to_disk(node, reason) < 0)
    return -EPROTO;

  return node->read(offset, buffer_size, buffer);
}

int FileSystem::write_file(const string &reason, const string &filepath, const long offset, const size_t data_size, const char *data) {
  Filenode *node = dynamic_cast<Filenode*>(this->supernode->retrieve_node(filepath));
  if (node == NULL)
    return -ENOENT;
  if (!node->has_user_rights(Node::WRITE_RIGHT, this->current_user))
    return -EACCES;

  if (e_append_audit_to_disk(node, reason) < 0)
    return -EPROTO;

  int ret = node->write(offset, data_size, data);
  if (ret < 0)
    return ret;

  if (e_write_meta_to_disk(node) < 0)
    return -EPROTO;
  if (e_write_file_to_disk(node, offset, data_size) < 0)
    return -EPROTO;

  return ret;
}

int FileSystem::unlink(const string &filepath) {
  Filenode *node = dynamic_cast<Filenode*>(this->supernode->retrieve_node(filepath));
  if (node == NULL)
    return -ENOENT;
  if (!node->has_user_rights(Filenode::OWNER_RIGHT, this->current_user))
    return -EACCES;

  if (delete_from_disk(node, CONTENT_DIR) < 0)
    return -EPROTO;
  if (delete_from_disk(node, META_DIR) < 0)
    return -EPROTO;

  this->supernode->remove_node_entry(node);

  if (delete_from_disk(node, AUDIT_DIR) < 0)
    return -EPROTO;

  delete node;
  return 0;
}


int FileSystem::load_metadata(Node *parent) {
  if (parent->node_type == Node::FILENODE_TYPE)
    return -1;

  for (auto itr = parent->node_entries->begin(); itr != parent->node_entries->end(); itr++) {
    string child_uuid = itr->first;

    char *buffer = NULL;
    int buffer_size = e_load_meta_from_disk(child_uuid, &buffer);
    if (buffer_size < 0)
      return -1;

    Filenode *child = new Filenode(child_uuid, this->root_key, this->block_size);
    if (child->e_load(buffer_size, buffer) < 0)
      return -1;
    if (parent->link_node_entry(child_uuid, child) < 0)
      return -1;

    free(buffer);
  }
  return 0;
}

int FileSystem::load_content(Node *parent) {
  if (parent->node_type == Node::FILENODE_TYPE)
    return -1;

  for (auto itr = parent->node_entries->begin(); itr != parent->node_entries->end(); itr++) {
    if (itr->second->node_type == Node::FILENODE_TYPE) {
      Filenode *node = dynamic_cast<Filenode*>(itr->second);

      int offset = 0, buffer_size = 0;
      do {
        char *buffer = NULL;
        int buffer_size = e_load_file_from_disk(node->uuid, offset, &buffer);
        if (buffer_size < 0)
          return -1;
        else if (buffer_size > 0) {
          if (node->e_load_content(offset, buffer_size, buffer) < 0)
            return -1;

          free(buffer);
        }
      } while (buffer_size != 0);
    }
  }
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
  size_t e_size = node->e_content_size(up_offset, up_size); char cypher[e_size];
  int offset = node->e_dump_content(up_offset, up_size, e_size, cypher);
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

int FileSystem::e_load_file_from_disk(const string &uuid, const long offset, char **buffer) {
  int ret = 0;
  if (ocall_file_size(&ret, (char*)this->CONTENT_DIR.c_str(), (char*)uuid.c_str()) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  size_t buffer_size = ret-offset;
  if (buffer_size == 0)
    return 0;
  else if (buffer_size > this->block_size)
    buffer_size = block_size;

  *buffer = new char[buffer_size];
  if (ocall_load_file(&ret, (char*)this->CONTENT_DIR.c_str(), (char*)uuid.c_str(), offset, buffer_size, *buffer) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  return ret;
}


int FileSystem::delete_from_disk(Node *node, const string &from_dir) {
  int ret;
  if (ocall_delete_from_dir(&ret, (char*)from_dir.c_str(), (char*)node->uuid.c_str()) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  return 0;
}
