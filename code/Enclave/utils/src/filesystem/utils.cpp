#include "../../headers/filesystem.hpp"


Node* FileSystem::retrieve_node(const string &path) {
  if (this->supernode->relative_path.compare(path) == 0)
    return this->supernode;
  else if (this->loaded_node->find(path) != this->loaded_node->end())
    return this->loaded_node->find(path)->second;
  else {
    Node *node = _retrieve_node(this->supernode, sgx_get_child_path(path));
    if (node != NULL)
      this->loaded_node->insert(pair<string, Node*>(path, node));
    return node;
  }
}
Node *FileSystem::_retrieve_node(Node *parent, const string &path) {
  string parent_path = sgx_get_parent_path(path);
  string child_path = sgx_get_child_path(path);

  auto it = parent->node_entries->find(parent_path);
  // if (parent->relative_path.compare(path) == 0 || path.compare("") == 0)
  if (path.compare("") == 0)
    return parent;
  else if (it == parent->node_entries->end())
    return NULL;
  else {
    Node *children = this->load_metadata(it->second);
    if (children == NULL)
      return NULL;
    if (parent->type != LAUXUS_SUPERNODE)
      delete parent; // only freeing dirnode
    return this->_retrieve_node(children, child_path);
  }
}

void FileSystem::free_node(const string &path) {
  if (this->supernode->relative_path.compare(path) != 0) {
    auto it = this->loaded_node->find(path);
    if (it != this->loaded_node->end()) {
      if (it->second->type == LAUXUS_FILENODE)
        delete (Filenode*)it->second;
      else if (it->second->type == LAUXUS_FILENODE)
        delete (Dirnode*)it->second;
      this->loaded_node->erase(it);
    }
  }
}
