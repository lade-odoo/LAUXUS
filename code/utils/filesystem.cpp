#include "../utils/filesystem.hpp"
#include "../utils/encryption.hpp"
#include "../utils/metadata/node.hpp"
#include "../utils/metadata/filenode.hpp"
#include "../utils/metadata/supernode.hpp"

#include <cerrno>
#include <string>
#include <vector>
#include <map>



FileSystem::FileSystem(AES_GCM_context *root_key, Supernode *supernode, size_t block_size=FileSystem::DEFAULT_BLOCK_SIZE) {
  this->root_key = root_key;
  this->supernode = supernode;
  this->block_size = block_size;

  this->current_user = NULL;
  this->files = new std::map<std::string, Filenode*>();
}

Filenode* FileSystem::retrieve_node(const std::string &filename) {
  auto entry = this->files->find(filename);
  if (entry == this->files->end())
    return NULL;
  return entry->second;
}

Filenode* FileSystem::retrieve_node_with_uuid(const std::string &uuid) {
  for (auto it = this->files->begin(); it != this->files->end(); ++it)
    if (it->second->uuid.compare(uuid) == 0)
      return it->second;
  return NULL;
}


int FileSystem::edit_user_policy(const std::string &filename, const unsigned char policy, const int user_id) {
  Filenode *node = FileSystem::retrieve_node(filename);
  User *user = this->supernode->retrieve_user(user_id);
  if (node == NULL || user == NULL)
    return -ENOENT;
  if (!node->is_user_allowed(Filenode::OWNER_POLICY, this->current_user))
    return -EACCES;

  return node->edit_user_policy(policy, user);
}


std::vector<std::string> FileSystem::readdir() {
  std::vector<std::string> entries;

  for (auto itr = this->files->begin(); itr != this->files->end(); itr++) {
    Filenode *filenode = itr->second;
    if (filenode->getattr(this->current_user) != 0)
      entries.push_back(filenode->path);
  }

  return entries;
}


int FileSystem::get_uuid(const std::string &filename, const size_t buffer_size, char *buffer) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;

  int uuid_len = node->uuid.length() + 1;
  if (buffer_size < uuid_len)
    return -1;

  std::memcpy(buffer, node->uuid.c_str(), uuid_len);
  return 0;
}

bool FileSystem::isfile(const std::string &filename) {
  return this->files->find(filename) != this->files->end();
}

int FileSystem::file_size(const std::string &filename) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  return node->file_size();
}

int FileSystem::getattr(const std::string &filename) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  return node->getattr(this->current_user);
}

int FileSystem::create_file(const std::string &filename) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node != NULL)
    return -EEXIST;

  std::string uuid = Node::generate_uuid();
  node = new Filenode(uuid, filename, this->root_key, this->block_size);
  node->edit_user_policy(Filenode::OWNER_POLICY, this->current_user);
  this->files->insert(std::pair<std::string, Filenode*>(filename, node));
  return 0;
}

int FileSystem::read_file(const std::string &filename, const long offset, const size_t buffer_size, char *buffer) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  if (!node->is_user_allowed(Filenode::READ_POLICY, this->current_user))
    return -EACCES;

  return node->read(offset, buffer_size, buffer);
}

int FileSystem::write_file(const std::string &filename, const long offset, const size_t data_size, const char *data) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  if (!node->is_user_allowed(Filenode::WRITE_POLICY, this->current_user))
    return -EACCES;

  return node->write(offset, data_size, data);
}

int FileSystem::unlink(const std::string &filename) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  if (!node->is_user_allowed(Filenode::OWNER_POLICY, this->current_user))
    return -EACCES;

  delete node;
  this->files->erase(filename);
  return 0;
}


int FileSystem::e_metadata_size(const std::string &filename) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  return node->e_size();
}

int FileSystem::e_dump_metadata(const std::string &filename, const size_t buffer_size, char *buffer) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  return node->e_dump(buffer_size, buffer);
}

int FileSystem::e_load_metadata(const std::string &uuid, const size_t buffer_size, const char *buffer) {
  Filenode *node = FileSystem::retrieve_node_with_uuid(uuid);
  if (node != NULL)
    return -EEXIST;

  node = new Filenode(uuid, this->root_key, this->block_size);
  node->e_load(buffer_size, buffer);
  this->files->insert(std::pair<std::string, Filenode*>(node->path, node));
  return 0;
}


int FileSystem::e_file_size(const std::string &filename, const long up_offset, const size_t up_size) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  return node->e_content_size(up_offset, up_size);
}

int FileSystem::e_dump_file(const std::string &filename, const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  return node->e_dump_content(up_offset, up_size, buffer_size, buffer);
}

int FileSystem::e_load_file(const std::string &uuid, const long offset, const size_t buffer_size, const char *buffer) {
  Filenode *node = FileSystem::retrieve_node_with_uuid(uuid);
  if (node == NULL)
    return -ENOENT;
  return node->e_load_content(offset, buffer_size, buffer);
}
