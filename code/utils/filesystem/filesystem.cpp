#include "filesystem.hpp"
#include "../encryption/aes_gcm.hpp"
#include "../node/node.hpp"
#include "../node/filenode.hpp"
#include "../node/dirnode.hpp"
#include "../node/supernode.hpp"
#include "../node/node_audit.hpp"

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>
#include <memory>

using namespace std;



FileSystem::FileSystem(AES_GCM_context *root_key, AES_GCM_context *audit_root_key,
                        Supernode *supernode, size_t block_size=FileSystem::DEFAULT_BLOCK_SIZE) {
  this->root_key = root_key;
  this->audit_root_key = audit_root_key;
  this->supernode = supernode;
  this->block_size = block_size;
  this->current_user = NULL;
}
FileSystem::FileSystem(AES_GCM_context *root_key, AES_GCM_context *audit_root_key,
        size_t block_size):FileSystem::FileSystem(root_key, audit_root_key, NULL, block_size) {}

FileSystem::~FileSystem() {
  delete this->root_key;
  delete this->audit_root_key;
  delete this->supernode;
}

void FileSystem::init_dumping_folders(const string &CONTENT_DIR, const string &META_DIR, const string &AUDIT_DIR) {
  this->CONTENT_DIR = CONTENT_DIR;
  this->META_DIR = META_DIR;
  this->AUDIT_DIR = AUDIT_DIR;
}

void FileSystem::link_supernode(Supernode *node) {
  this->supernode = node;
}


int FileSystem::edit_user_entitlement(const string &path, const unsigned char rights, const string user_uuid) {
  vector<Node*> to_release;
  Node *node = this->retrieve_node(path); to_release.push_back(node);
  User *user = this->supernode->retrieve_user(user_uuid);
  if (node == NULL || user == NULL)
    return _return_and_free(-ENOENT, to_release);
  if (!node->has_user_rights(Node::OWNER_RIGHT, this->current_user))
    return _return_and_free(-EACCES, to_release);

  int ret = node->edit_user_entitlement(rights, user);
  if (ret < 0)
    return _return_and_free(ret, to_release);
  if (e_write_meta_to_disk(node) < 0)
    return _return_and_free(-EPROTO, to_release);

  return _return_and_free(ret, to_release);
}

int FileSystem::get_rights(const string &path) {
  vector<Node*> to_release;
  Node *node = this->retrieve_node(path); to_release.push_back(node);
  if (node == NULL)
    return _return_and_free(-ENOENT, to_release);

  int ret = node->get_rights(this->current_user);
  return _return_and_free(ret, to_release);
}

int FileSystem::entry_type(const string &path) {
  vector<Node*> to_release;
  Node *node = this->retrieve_node(path); to_release.push_back(node);
  if (node == NULL)
    return _return_and_free(-ENOENT, to_release);

  if (node->node_type == Node::SUPERNODE_TYPE || node->node_type == Node::DIRNODE_TYPE)
    return _return_and_free(EISDIR, to_release);
  return _return_and_free(EEXIST, to_release);
}


int FileSystem::file_size(const string &filepath) {
  vector<Node*> to_release;
  Filenode *node = dynamic_cast<Filenode*>(this->retrieve_node(filepath)); to_release.push_back(node);
  if (node == NULL)
    return _return_and_free(-ENOENT, to_release);

  return _return_and_free(node->content->size, to_release);
}

int FileSystem::create_file(const string &reason, const string &filepath) {
  vector<Node*> to_release;
  Node *node = this->retrieve_node(filepath); to_release.push_back(node);
  if (node != NULL)
    return _return_and_free(-EEXIST, to_release);

  // relative path of the file
  string parent_path = FileSystem::get_directory_path(filepath);
  string relative_path = FileSystem::get_relative_path(filepath);
  Node *parent = this->retrieve_node(parent_path); to_release.push_back(parent);
  if (parent == NULL)
    return _return_and_free(-ENOENT, to_release);

  // create node
  string uuid = Node::generate_uuid();
  Filenode *filenode = new Filenode(uuid, relative_path, this->root_key, this->block_size); to_release.push_back(filenode);
  filenode->edit_user_entitlement(Node::OWNER_RIGHT, this->current_user);
  parent->add_node_entry(filenode->relative_path, filenode->uuid);

  if (e_append_audit_to_disk(parent, reason) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (e_write_meta_to_disk(parent) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (e_append_audit_to_disk(filenode, reason) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (e_write_meta_to_disk(filenode) < 0)
    return _return_and_free(-EPROTO, to_release);

  return _return_and_free(0, to_release);
}

int FileSystem::read_file(const string &reason, const string &filepath, const long offset, const size_t buffer_size, char *buffer) {
  vector<Node*> to_release;
  Filenode *node = dynamic_cast<Filenode*>(this->retrieve_node(filepath)); to_release.push_back(node);
  if (node == NULL)
    return _return_and_free(-ENOENT, to_release);
  if (!node->has_user_rights(Node::READ_RIGHT, this->current_user))
    return _return_and_free(-EACCES, to_release);

  if (e_append_audit_to_disk(node, reason) < 0)
    return _return_and_free(-EPROTO, to_release);

  if (this->load_content(node, offset, buffer_size) < 0)
    return _return_and_free(-EPROTO, to_release);
  return _return_and_free(node->content->read(offset, buffer_size, buffer), to_release);
}

int FileSystem::write_file(const string &reason, const string &filepath, const long offset, const size_t data_size, const char *data) {
  vector<Node*> to_release;
  Filenode *node = dynamic_cast<Filenode*>(this->retrieve_node(filepath)); to_release.push_back(node);
  if (node == NULL)
    return _return_and_free(-ENOENT, to_release);
  if (!node->has_user_rights(Node::WRITE_RIGHT, this->current_user))
    return _return_and_free(-EACCES, to_release);

  if (e_append_audit_to_disk(node, reason) < 0)
    return _return_and_free(-EPROTO, to_release);

  if (this->load_content(node, offset, data_size) < 0)
    return _return_and_free(-EPROTO, to_release);
  int ret = node->content->write(offset, data_size, data);
  if (ret < 0)
    return _return_and_free(ret, to_release);

  if (e_write_meta_to_disk(node) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (e_write_file_to_disk(node, offset, data_size) < 0)
    return _return_and_free(-EPROTO, to_release);

  return _return_and_free(ret, to_release);
}

int FileSystem::unlink(const string &reason, const string &filepath) {
  vector<Node*> to_release;
  string parent_path = FileSystem::get_directory_path(filepath);
  string relative_path = FileSystem::get_relative_path(filepath);
  Node *parent = this->retrieve_node(parent_path); to_release.push_back(parent);
  if (parent == NULL)
    return _return_and_free(-ENOENT, to_release);

  auto it = parent->node_entries->find(relative_path);
  if (it == parent->node_entries->end())
    return _return_and_free(-ENOENT, to_release);

  Filenode *children = dynamic_cast<Filenode*>(this->load_metadata(it->second)); to_release.push_back(children);
  if (children == NULL)
    return _return_and_free(-ENOENT, to_release);
  if (!children->has_user_rights(Node::OWNER_RIGHT, this->current_user))
    return _return_and_free(-EACCES, to_release);
  parent->remove_node_entry(children->relative_path);

  if (delete_from_disk(children, CONTENT_DIR) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (delete_from_disk(children, META_DIR) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (delete_from_disk(children, AUDIT_DIR) < 0)
    return _return_and_free(-EPROTO, to_release);

  if (e_append_audit_to_disk(parent, reason) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (e_write_meta_to_disk(parent) < 0)
    return _return_and_free(-EPROTO, to_release);

  return _return_and_free(0, to_release);
}


vector<string> FileSystem::readdir(const string &path) {
  vector<Node*> to_release;
  vector<string> entries;

  Node *parent = this->retrieve_node(path); to_release.push_back(parent);
  for (auto itr = parent->node_entries->begin(); itr != parent->node_entries->end(); itr++) {
    Node *children = this->load_metadata(itr->second); to_release.push_back(children);
    if (children->get_rights(this->current_user) > 0)
      entries.push_back(children->relative_path);
  }

  _return_and_free(0, to_release);
  return entries;
}

int FileSystem::create_directory(const string &reason, const string &dirpath) {
  vector<Node*> to_release;
  Node *node = this->retrieve_node(dirpath); to_release.push_back(node);
  if (node != NULL)
    return _return_and_free(-EEXIST, to_release);

  // relative path of the file
  string parent_path = FileSystem::get_directory_path(dirpath);
  string relative_path = FileSystem::get_relative_path(dirpath);
  Node *parent = this->retrieve_node(parent_path); to_release.push_back(parent);
  if (parent == NULL)
    return _return_and_free(-ENOENT, to_release);

  // create node
  string uuid = Node::generate_uuid();
  Dirnode *dirnode = new Dirnode(uuid, relative_path, this->root_key); to_release.push_back(parent);
  dirnode->edit_user_entitlement(Node::OWNER_RIGHT, this->current_user);
  parent->add_node_entry(dirnode->relative_path, dirnode->uuid);

  if (e_append_audit_to_disk(parent, reason) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (e_write_meta_to_disk(parent) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (e_append_audit_to_disk(dirnode, reason) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (e_write_meta_to_disk(dirnode) < 0)
    return _return_and_free(-EPROTO, to_release);

  return _return_and_free(0, to_release);
}

int FileSystem::rm_directory(const string &reason, const string &dirpath) {
  vector<Node*> to_release;
  string parent_path = FileSystem::get_directory_path(dirpath);
  string relative_path = FileSystem::get_relative_path(dirpath);
  Node *parent = this->retrieve_node(parent_path); to_release.push_back(parent);
  if (parent == NULL)
    return _return_and_free(-ENOENT, to_release);

  auto it = parent->node_entries->find(relative_path);
  if (it == parent->node_entries->end())
    return _return_and_free(-ENOENT, to_release);
  Dirnode *children = dynamic_cast<Dirnode*>(this->load_metadata(it->second)); to_release.push_back(children);
  if (children == NULL)
    return _return_and_free(-ENOENT, to_release);
  if (!children->has_user_rights(Node::OWNER_RIGHT, this->current_user))
    return _return_and_free(-EACCES, to_release);
  if (children->node_entries->size() != 0)
    return _return_and_free(-ENOTEMPTY, to_release);

  parent->remove_node_entry(relative_path);
  if (e_append_audit_to_disk(parent, reason) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (e_write_meta_to_disk(parent) < 0)
    return _return_and_free(-EPROTO, to_release);

  // now we can delete the dir informations
  if (delete_from_disk(children, AUDIT_DIR) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (delete_from_disk(children, CONTENT_DIR) < 0)
    return _return_and_free(-EPROTO, to_release);
  if (delete_from_disk(children, META_DIR) < 0)
    return _return_and_free(-EPROTO, to_release);

  return _return_and_free(0, to_release);
}


int FileSystem::_return_and_free(int rt, const vector<Node*> &nodes) {
  for (auto it = nodes.begin(); it != nodes.end(); ++it) {
    Node *node = *it;
    if (node != NULL && node->node_type != Node::SUPERNODE_TYPE)
      delete node;
  }
  return rt;
}
