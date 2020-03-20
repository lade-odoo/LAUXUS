#include "../utils/filesystem.hpp"
#include "../utils/metadata.hpp"

#include <cerrno>
#include <string>
#include <vector>
#include <map>


FileSystem::FileSystem(const char* mount_dir, size_t block_size=FileSystem::DEFAULT_BLOCK_SIZE) {
  this->block_size = block_size;
  this->mount_dir = mount_dir;

  this->files = new std::map<std::string, Filenode*>();
}

Filenode* FileSystem::retrieve_node(const std::string &filename) {
  auto entry = this->files->find(filename);
  if (entry == this->files->end())
    return NULL;
  return entry->second;
}


std::vector<std::string> FileSystem::readdir() {
  std::vector<std::string> entries;

  for (auto itr = this->files->begin(); itr != this->files->end(); itr++) {
    Filenode *filenode = itr->second;
    entries.push_back(filenode->filename);
  }

  return entries;
}


bool FileSystem::isfile(const std::string &filename) {
  return this->files->find(filename) != this->files->end();
}

size_t FileSystem::file_size(const std::string &filename) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  return node->size();
}

int FileSystem::create_file(const std::string &filename) {
  Filenode *node = new Filenode(filename, this->block_size);
  this->files->insert(std::pair<std::string, Filenode*>(filename, node));
  return 0;
}

int FileSystem::read_file(const std::string &filename, const long offset, const size_t buffer_size, char *buffer) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  return node->read(offset, buffer_size, buffer);
}

int FileSystem::write_file(const std::string &filename, const long offset, const size_t data_size, const char *data) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  return node->write(offset, data_size, data);
}

int FileSystem::unlink(const std::string &filename) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  delete node;
  this->files->erase(filename);
  return 0;
}


int FileSystem::metadata_size(const std::string &filename) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  return node->metadata_size();
}

int FileSystem::dump_metadata(const std::string &filename, const size_t buffer_size, char *buffer) {
  Filenode *node = FileSystem::retrieve_node(filename);
  if (node == NULL)
    return -ENOENT;
  return node->dump_metadata(buffer_size, buffer);
}
