#include "filesystem.hpp"
#include <string>

using namespace std;


Node* FileSystem::retrieve_node(const string &path) {
  if (this->supernode->relative_path.compare(path) == 0)
    return this->supernode;
  else
    return _retrieve_node(this->supernode, FileSystem::get_child_path(path));
}

Node *FileSystem::_retrieve_node(Node *parent, const string &path) {
  string parent_path = FileSystem::get_parent_path(path);
  string child_path = FileSystem::get_child_path(path);

  auto it = parent->node_entries->find(parent_path);
  if (parent->relative_path.compare(path) == 0 || path.compare("") == 0)
    return parent;
  else if (it == parent->node_entries->end())
    return NULL;
  else {
    Node *children = this->load_metadata(it->second);
    if (children == NULL)
      return NULL;
    if (parent->node_type != Node::SUPERNODE_TYPE)
      delete parent;
    return this->_retrieve_node(children, child_path);
  }
}


string FileSystem::get_directory_path(const string &path) {
  string cleaned = clean_path(path);
  size_t index = cleaned.find_last_of("/");
  return clean_path(cleaned.substr(0, index + 1));
}

string FileSystem::get_relative_path(const string &path) {
  string cleaned = clean_path(path);
  size_t index = cleaned.find_last_of("/");
  return clean_path(cleaned.substr(index + 1));
}

string FileSystem::get_parent_path(const string &path) {
  string cleaned = clean_path(path);
  size_t index = cleaned.find("/");
  if (index == string::npos)
    return path;
  return clean_path(cleaned.substr(0, index + 1));
}

string FileSystem::get_child_path(const string &path) {
  string cleaned = clean_path(path);
  size_t index = cleaned.find("/");
  if (index == string::npos)
    return "";
  return clean_path(cleaned.substr(index + 1));
}

string FileSystem::clean_path(const string &path) {
  string trimmed = path;
  size_t position;
  while ((position = trimmed.find("//")) != string::npos)
    trimmed = trimmed.replace(position, 2, "/");
  while (trimmed.length() > 1 && trimmed.back() == '/')
    trimmed.pop_back();

  return trimmed;
}
