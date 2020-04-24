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
  unique_ptr<Node, NodeDeleter> node(this->retrieve_node(path));
  User *user = this->supernode->retrieve_user(user_uuid);
  if (node == NULL || user == NULL)
    return -ENOENT;
  if (!node->has_user_rights(Node::OWNER_RIGHT, this->current_user))
    return -EACCES;

  int ret = node->edit_user_entitlement(rights, user);
  if (ret < 0)
    return ret;
  if (e_write_meta_to_disk(node.get()) < 0)
    return -EPROTO;

  return ret;
}

int FileSystem::get_rights(const string &path) {
  unique_ptr<Node, NodeDeleter> node(this->retrieve_node(path));
  if (node == NULL)
    return -ENOENT;

  int ret = node->get_rights(this->current_user);
  return ret;
}

int FileSystem::entry_type(const string &path) {
  unique_ptr<Node, NodeDeleter> node(this->retrieve_node(path));
  if (node == NULL)
    return -ENOENT;

  if (node->node_type == Node::SUPERNODE_TYPE || node->node_type == Node::DIRNODE_TYPE)
    return EISDIR;
  return EEXIST;
}


int FileSystem::file_size(const string &filepath) {
  unique_ptr<Filenode> node(dynamic_cast<Filenode*>(this->retrieve_node(filepath)));
  if (node == NULL)
    return -ENOENT;

  return node->content->size;
}

int FileSystem::create_file(const string &reason, const string &filepath) {
  unique_ptr<Node, NodeDeleter> node(this->retrieve_node(filepath));
  if (node != NULL)
    return -EEXIST;

  // relative path of the file
  string parent_path = FileSystem::get_directory_path(filepath);
  string relative_path = FileSystem::get_relative_path(filepath);
  unique_ptr<Node, NodeDeleter> parent(this->retrieve_node(parent_path));
  if (parent == NULL)
    return -ENOENT;

  // create node
  string uuid = Node::generate_uuid();
  unique_ptr<Filenode> filenode(new Filenode(uuid, relative_path, this->root_key, this->block_size));
  filenode->edit_user_entitlement(Node::OWNER_RIGHT, this->current_user);
  parent->add_node_entry(filenode->relative_path, filenode->uuid);

  if (e_append_audit_to_disk(parent.get(), reason) < 0)
    return -EPROTO;
  if (e_write_meta_to_disk(parent.get()) < 0)
    return -EPROTO;
  if (e_append_audit_to_disk(filenode.get(), reason) < 0)
    return -EPROTO;
  if (e_write_meta_to_disk(filenode.get()) < 0)
    return -EPROTO;

  return 0;
}

int FileSystem::read_file(const string &reason, const string &filepath, const long offset, const size_t buffer_size, char *buffer) {
  unique_ptr<Filenode> node(dynamic_cast<Filenode*>(this->retrieve_node(filepath)));
  if (node == NULL)
    return -ENOENT;
  if (!node->has_user_rights(Node::READ_RIGHT, this->current_user))
    return -EACCES;

  if (e_append_audit_to_disk(node.get(), reason) < 0)
    return -EPROTO;

  if (this->load_content(node.get(), offset, buffer_size) < 0)
    return -EPROTO;
  if (node->content->size < buffer_size+offset)
    return -EPROTO;
  return node->content->read(offset, buffer_size, buffer);
}

int FileSystem::write_file(const string &reason, const string &filepath, const long offset, const size_t data_size, const char *data) {
  unique_ptr<Filenode> node(dynamic_cast<Filenode*>(this->retrieve_node(filepath)));
  if (node == NULL)
    return -ENOENT;
  if (!node->has_user_rights(Node::WRITE_RIGHT, this->current_user))
    return -EACCES;

  if (e_append_audit_to_disk(node.get(), reason) < 0)
    return -EPROTO;

  if (this->load_content(node.get(), offset, data_size) < 0)
    return -EPROTO;
  int ret = node->content->write(offset, data_size, data);
  if (ret < 0)
    return ret;

  if (e_write_meta_to_disk(node.get()) < 0)
    return -EPROTO;
  if (e_write_file_to_disk(node.get(), offset, data_size) < 0)
    return -EPROTO;

  return ret;
}

int FileSystem::unlink(const string &reason, const string &filepath) {
  string parent_path = FileSystem::get_directory_path(filepath);
  string relative_path = FileSystem::get_relative_path(filepath);
  unique_ptr<Node, NodeDeleter> parent(this->retrieve_node(parent_path));
  if (parent == NULL)
    return -ENOENT;

  auto it = parent->node_entries->find(relative_path);
  if (it == parent->node_entries->end())
    return -ENOENT;

  unique_ptr<Filenode> children(dynamic_cast<Filenode*>(this->load_metadata(it->second)));
  if (children == NULL)
    return -ENOENT;
  if (!children->has_user_rights(Node::OWNER_RIGHT, this->current_user))
    return -EACCES;
  parent->remove_node_entry(children->relative_path);

  if (delete_from_disk(children.get(), CONTENT_DIR) < 0)
    return -EPROTO;
  if (delete_from_disk(children.get(), META_DIR) < 0)
    return -EPROTO;
  if (delete_from_disk(children.get(), AUDIT_DIR) < 0)
    return -EPROTO;

  if (e_append_audit_to_disk(parent.get(), reason) < 0)
    return -EPROTO;
  if (e_write_meta_to_disk(parent.get()) < 0)
    return -EPROTO;

  return 0;
}


vector<string> FileSystem::readdir(const string &path) {
  vector<string> entries;

  unique_ptr<Node, NodeDeleter> parent(this->retrieve_node(path));
  for (auto itr = parent->node_entries->begin(); itr != parent->node_entries->end(); itr++) {
    unique_ptr<Node, NodeDeleter> children(this->load_metadata(itr->second));
    if (children->get_rights(this->current_user) > 0)
      entries.push_back(children->relative_path);
  }

  return entries;
}

int FileSystem::create_directory(const string &reason, const string &dirpath) {
  unique_ptr<Node, NodeDeleter> node(this->retrieve_node(dirpath));
  if (node != NULL)
    return -EEXIST;

  // relative path of the file
  string parent_path = FileSystem::get_directory_path(dirpath);
  string relative_path = FileSystem::get_relative_path(dirpath);
  unique_ptr<Node, NodeDeleter> parent(this->retrieve_node(parent_path));
  if (parent == NULL)
    return -ENOENT;

  // create node
  string uuid = Node::generate_uuid();
  unique_ptr<Dirnode> dirnode(new Dirnode(uuid, relative_path, this->root_key));
  dirnode->edit_user_entitlement(Node::OWNER_RIGHT, this->current_user);
  parent->add_node_entry(dirnode->relative_path, dirnode->uuid);

  if (e_append_audit_to_disk(parent.get(), reason) < 0)
    return -EPROTO;
  if (e_write_meta_to_disk(parent.get()) < 0)
    return -EPROTO;
  if (e_append_audit_to_disk(dirnode.get(), reason) < 0)
    return -EPROTO;
  if (e_write_meta_to_disk(dirnode.get()) < 0)
    return -EPROTO;

  return 0;
}

int FileSystem::rm_directory(const string &reason, const string &dirpath) {
  string parent_path = FileSystem::get_directory_path(dirpath);
  string relative_path = FileSystem::get_relative_path(dirpath);
  unique_ptr<Node, NodeDeleter> parent(this->retrieve_node(parent_path));
  if (parent == NULL)
    return -ENOENT;

  auto it = parent->node_entries->find(relative_path);
  if (it == parent->node_entries->end())
    return -ENOENT;
  unique_ptr<Dirnode> children(dynamic_cast<Dirnode*>(this->load_metadata(it->second)));
  if (children == NULL)
    return -ENOENT;
  if (!children->has_user_rights(Node::OWNER_RIGHT, this->current_user))
    return -EACCES;
  if (children->node_entries->size() != 0)
    return -ENOTEMPTY;

  parent->remove_node_entry(relative_path);
  if (e_append_audit_to_disk(parent.get(), reason) < 0)
    return -EPROTO;
  if (e_write_meta_to_disk(parent.get()) < 0)
    return -EPROTO;

  // now we can delete the dir informations
  if (delete_from_disk(children.get(), AUDIT_DIR) < 0)
    return -EPROTO;
  if (delete_from_disk(children.get(), CONTENT_DIR) < 0)
    return -EPROTO;
  if (delete_from_disk(children.get(), META_DIR) < 0)
    return -EPROTO;

  return 0;
}
