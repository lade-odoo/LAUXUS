#include "../../headers/filesystem.hpp"


FileSystem::FileSystem(lauxus_gcm_t *root_key, lauxus_gcm_t *audit_root_key, Supernode *supernode,
        const string &CONTENT_DIR, const string &META_DIR, const string &AUDIT_DIR,
        size_t block_size=DEFAULT_BLOCK_SIZE) {
  this->root_key = root_key;
  this->audit_root_key = audit_root_key;
  this->supernode = supernode;
  this->block_size = block_size;
  this->current_user = NULL;

  this->CONTENT_DIR = CONTENT_DIR;
  this->META_DIR = META_DIR;
  this->AUDIT_DIR = AUDIT_DIR;

  this->loaded_node = new map<string, Node*>();
}

FileSystem::~FileSystem() {
  free(this->root_key);
  free(this->audit_root_key);

  for (auto it = this->loaded_node->begin(); it != this->loaded_node->end(); ++it)
    delete it->second;
  delete this->loaded_node;
  delete this->supernode;
}


int FileSystem::edit_user_entitlement(const string &path, lauxus_right_t rights, const lauxus_uuid_t *u_uuid) {
  Node *node = this->retrieve_node(path);
  User *user = this->supernode->retrieve_user(u_uuid);
  if (node == NULL || user == NULL)
    return -ENOENT;
  if (!node->has_user_rights(lauxus_owner_right(), this->current_user)) {
    this->free_node(path);
    return -EACCES;
  }

  if (node->edit_user_rights(rights, user) < 0)
    goto err;

  node->update_ctime();
  if (e_write_meta_to_disk(node) < 0)
    goto err;

  this->free_node(path);
  return 0;

err:
  this->free_node(path);
  return -EPROTO;
}

int FileSystem::get_rights(const string &path, lauxus_right_t *rights) {
  Node *node = this->retrieve_node(path);
  if (node == NULL)
    return -ENOENT;

  *rights = node->get_rights(this->current_user);
  this->free_node(path);
  return 0;
}

int FileSystem::entry_type(const string &path) {
  Node *node = this->retrieve_node(path);
  if (node == NULL)
    return -ENOENT;

  int ret = (node->type == LAUXUS_SUPERNODE || node->type == LAUXUS_DIRNODE) ? EISDIR : EEXIST;
  this->free_node(path);
  return ret;
}

int FileSystem::get_times(const string &path, time_t *atime, time_t *mtime, time_t *ctime) {
  Node *node = this->retrieve_node(path);
  if (node == NULL)
    return -ENOENT;

  memcpy(atime, &(node->atime), sizeof(time_t));
  memcpy(mtime, &(node->mtime), sizeof(time_t));
  memcpy(ctime, &(node->ctime), sizeof(time_t));

  this->free_node(path);
  return 0;
}


int FileSystem::file_size(const string &filepath) {
  Filenode *node = dynamic_cast<Filenode*>(this->retrieve_node(filepath));
  if (node == NULL)
    return -ENOENT;

  int ret = node->content->size;
  this->free_node(filepath);
  return ret;
}

int FileSystem::open_file(const string &filepath, const lauxus_right_t asked_rights) {
  Filenode *node = dynamic_cast<Filenode*>(this->retrieve_node(filepath));
  if (node == NULL)
    return -ENOENT;
  if (!node->has_user_rights(asked_rights, this->current_user))
    return -EACCES;

  return 0;
}
int FileSystem::close_file(const string &filepath) {
  this->free_node(filepath);
  return 0;
}

int FileSystem::create_file(const string &reason, const string &filepath) {
  Node *node = this->retrieve_node(filepath);
  if (node != NULL) { // file already exists
    this->free_node(filepath);
    return -EEXIST;
  }

  // relative path of the file
  string parent_path = get_directory_path(filepath);
  string relative_path = get_relative_path(filepath);
  Node *parent = this->retrieve_node(parent_path);
  if (parent == NULL)
    return -ENOENT;

  // create node
  Filenode *filenode = new Filenode(relative_path, this->root_key, this->block_size);
  filenode->edit_user_rights(lauxus_owner_right(), this->current_user);
  parent->add_node_entry(filenode->relative_path, filenode->n_uuid);
  this->loaded_node->insert(pair<string, Node*>(filepath, filenode));

  filenode->update_atime(); filenode->update_mtime(); filenode->update_ctime();

  if (e_append_audit_to_disk(parent, reason) < 0 ||
      e_write_meta_to_disk(parent) < 0 ||
      e_append_audit_to_disk(filenode, reason) < 0 ||
      e_write_meta_to_disk(filenode) < 0)
    goto err;

  this->free_node(parent_path);
  return 0;

err:
  this->free_node(parent_path);
  return -EPROTO;
}

int FileSystem::read_file(const string &reason, const string &filepath, const long offset, const size_t buffer_size, uint8_t *buffer) {
  int ret;
  Filenode *node = dynamic_cast<Filenode*>(this->retrieve_node(filepath));
  if (node == NULL)
    return -ENOENT;
  if (!node->has_user_rights(lauxus_read_right(), this->current_user))
    return -EACCES;

  if (e_append_audit_to_disk(node, reason) < 0 ||
      this->load_content(node, offset, buffer_size) < 0)
    goto err;

  node->update_atime();
  if (e_write_meta_to_disk(node) < 0)
    goto err;
  ret = node->content->read(offset, buffer_size, buffer);
  node->content->free_loaded();
  return ret;

err:
  return -EPROTO;
}

int FileSystem::write_file(const string &reason, const string &filepath, const long offset, const size_t data_size, const uint8_t *data) {
  Filenode *node = dynamic_cast<Filenode*>(this->retrieve_node(filepath));
  if (node == NULL)
    return -ENOENT;
  if (!node->has_user_rights(lauxus_write_right(), this->current_user))
    return -EACCES;

  int ret = 0;
  if (e_append_audit_to_disk(node, reason) < 0 ||
      this->load_content(node, offset, data_size) < 0)
    goto err;

  ret = node->content->write(offset, data_size, data);
  if (ret < 0)
    return ret;

  node->update_mtime();
  if (e_write_meta_to_disk(node) < 0 ||
      e_write_file_to_disk(node, offset, data_size) < 0)
    goto err;

  node->content->free_loaded();
  return ret;

err:
  return -EPROTO;
}

int FileSystem::unlink(const string &reason, const string &filepath) {
  string parent_path = get_directory_path(filepath);
  string relative_path = get_relative_path(filepath);
  Node *parent = this->retrieve_node(parent_path);
  if (parent == NULL)
    return -ENOENT;

  auto it = parent->node_entries->find(relative_path);
  if (it == parent->node_entries->end()) {
    this->free_node(parent_path);
    return -ENOENT;
  }

  Filenode *children = dynamic_cast<Filenode*>(this->load_metadata(it->second));
  if (children == NULL)
    return -ENOENT;
  if (!children->has_user_rights(lauxus_owner_right(), this->current_user)) {
    delete children;
    this->free_node(parent_path);
    return -EACCES;
  }
  parent->remove_node_entry(children->relative_path);

  if (delete_from_disk(children, CONTENT_DIR) < 0 ||
      delete_from_disk(children, META_DIR) < 0 ||
      delete_from_disk(children, AUDIT_DIR) < 0 ||
      e_append_audit_to_disk(parent, reason) < 0 ||
      e_write_meta_to_disk(parent) < 0)
    goto err;

  delete children;
  this->free_node(filepath);
  this->free_node(parent_path);
  return 0;

err:
  delete children;
  this->free_node(parent_path);
  return -EPROTO;
}


vector<string> FileSystem::readdir(const string &path) {
  vector<string> entries;

  Node *parent = this->retrieve_node(path);
  for (auto itr = parent->node_entries->begin(); itr != parent->node_entries->end(); itr++) {
    Node *children = this->load_metadata(itr->second);
    if (children->has_user_rights(lauxus_owner_right(), this->current_user) ||
        children->has_user_rights(lauxus_read_right(), this->current_user) ||
        children->has_user_rights(lauxus_write_right(), this->current_user))
      entries.push_back(children->relative_path);
    delete children;
  }

  parent->update_atime();
  e_write_meta_to_disk(parent);
  this->free_node(path);
  return entries;
}

int FileSystem::create_directory(const string &reason, const string &dirpath) {
  Node *node = this->retrieve_node(dirpath);
  if (node != NULL) {
    this->free_node(dirpath);
    return -EEXIST;
  }

  // relative path of the file
  string parent_path = get_directory_path(dirpath);
  string relative_path = get_relative_path(dirpath);
  Node *parent = this->retrieve_node(parent_path);
  if (parent == NULL)
    return -ENOENT;

  // create node
  Dirnode *dirnode = new Dirnode(relative_path, this->root_key);
  dirnode->edit_user_rights(lauxus_owner_right(), this->current_user);
  parent->add_node_entry(dirnode->relative_path, dirnode->n_uuid);

  node->update_mtime();
  if (e_append_audit_to_disk(parent, reason) < 0 ||
      e_write_meta_to_disk(parent) < 0 ||
      e_append_audit_to_disk(dirnode, reason) < 0 ||
      e_write_meta_to_disk(dirnode) < 0)
    goto err;

  delete dirnode;
  this->free_node(parent_path);
  return 0;

err:
  delete dirnode;
  this->free_node(parent_path);
  return -EPROTO;
}

int FileSystem::rm_directory(const string &reason, const string &dirpath) {
  string parent_path = get_directory_path(dirpath);
  string relative_path = get_relative_path(dirpath);
  Node *parent = this->retrieve_node(parent_path);
  if (parent == NULL)
    return -ENOENT;

  auto it = parent->node_entries->find(relative_path);
  if (it == parent->node_entries->end()) {
    this->free_node(parent_path);
    return -ENOENT;
  }

  Dirnode *children = dynamic_cast<Dirnode*>(this->load_metadata(it->second));
  if (children == NULL) {
    this->free_node(parent_path);
    return -ENOENT;
  }
  if (!children->has_user_rights(lauxus_owner_right(), this->current_user)) {
    delete children; // not loaded with retrieve_node -> not listed in loaded nodes
    this->free_node(parent_path);
    return -EACCES;
  }
  if (children->node_entries->size() != 0) {
    delete children; // not loaded with retrieve_node -> not listed in loaded nodes
    this->free_node(parent_path);
    return -ENOTEMPTY;
  }

  parent->remove_node_entry(relative_path);
  if (e_append_audit_to_disk(parent, reason) < 0 ||
      e_write_meta_to_disk(parent) < 0 ||
      delete_from_disk(children, AUDIT_DIR) < 0 ||
      delete_from_disk(children, CONTENT_DIR) < 0 ||
      delete_from_disk(children, META_DIR) < 0)
    goto err;

  delete children;
  this->free_node(parent_path);
  return 0;

err:
  delete children;
  this->free_node(parent_path);
  return -EPROTO;
}
