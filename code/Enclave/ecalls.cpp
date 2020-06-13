#include "ecalls.hpp"

static FileSystem* FILE_SYSTEM;


/************************ Control Plane related ECALLS ************************/
int EMUL_EAPI sgx_new_user_keys(sgx_ec256_public_t *pk_u, sgx_ec256_private_t *sk_u) {
  return lauxus_generate_ECC_keys(pk_u, sk_u);
}


int EMUL_EAPI sgx_new_filesystem(const char *content_dir, const char* meta_dir, const char *audit_dir) {
  lauxus_gcm_t *root_key = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t)); lauxus_random_gcm(root_key);
  lauxus_gcm_t *audit_root_key = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t)); lauxus_random_gcm(audit_root_key);
  Supernode *node = new Supernode(root_key);
  FILE_SYSTEM = new FileSystem(root_key, audit_root_key, node,
                  content_dir, meta_dir, audit_dir, DEFAULT_BLOCK_SIZE);
  if (FILE_SYSTEM->e_write_meta_to_disk(FILE_SYSTEM->supernode) < 0)
    return -EPROTO;
  return 0;
}

int EMUL_EAPI sgx_load_filesystem(const sgx_sealed_data_t* rk_sealed_data, size_t rk_sealed_size,
          const sgx_sealed_data_t* ark_sealed_data, size_t ark_sealed_size,
          const uint8_t *e_supernode, size_t e_supernode_size,
          const char *content_dir, const char* meta_dir, const char *audit_dir) {

  lauxus_gcm_t *root_key = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t));
  lauxus_gcm_t *audit_root_key = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t));

  // unseal the rootkeys
  uint32_t rk_size = sizeof(lauxus_gcm_t);
  if (sgx_unseal_data(rk_sealed_data, NULL, NULL, (uint8_t*)root_key, &rk_size) != SGX_SUCCESS)
    return -EPROTO;
  if (sgx_unseal_data(ark_sealed_data, NULL, NULL, (uint8_t*)audit_root_key, &rk_size) != SGX_SUCCESS)
    return -EPROTO;

  // decrypt supernode
  Supernode *node = new Supernode(root_key);
  if (node->e_load(e_supernode_size, e_supernode) < 0)
    return -EPROTO;

  FILE_SYSTEM = new FileSystem(root_key, audit_root_key, node,
                  content_dir, meta_dir, audit_dir, DEFAULT_BLOCK_SIZE);
  return 0;
}

int EMUL_EAPI sgx_destroy_filesystem(const char *rk_path, const char *ark_path) {
  memset(FILE_SYSTEM->root_key->mac, 0x0, sizeof(sgx_aes_gcm_128bit_tag_t));
  memset(FILE_SYSTEM->audit_root_key->mac, 0x0, sizeof(sgx_aes_gcm_128bit_tag_t));

  size_t rk_seal_size = sizeof(lauxus_gcm_t) + sizeof(sgx_sealed_data_t);
  uint8_t sealed_rk[rk_seal_size]; uint8_t sealed_ark[rk_seal_size];

  if (sgx_seal_data(0, NULL, sizeof(lauxus_gcm_t), (uint8_t*)FILE_SYSTEM->root_key, rk_seal_size, (sgx_sealed_data_t*)sealed_rk) != SGX_SUCCESS)
    return -EPROTO;
  if (sgx_seal_data(0, NULL, sizeof(lauxus_gcm_t), (uint8_t*)FILE_SYSTEM->audit_root_key, rk_seal_size, (sgx_sealed_data_t*)sealed_ark) != SGX_SUCCESS)
    return -EPROTO;

  int ret;
  if ((ocall_dump(&ret, rk_path, rk_seal_size, sealed_rk) != SGX_SUCCESS || ret < 0) ||
      (ocall_dump(&ret, ark_path, rk_seal_size, sealed_ark) != SGX_SUCCESS || ret < 0))
    return -EPROTO;

  delete FILE_SYSTEM;
  return 0;
}


int EMUL_EAPI sgx_login(const sgx_ec256_private_t *sk_u, const lauxus_uuid_t *u_uuid) {
  User *user = FILE_SYSTEM->supernode->retrieve_user(u_uuid);
  if (user == NULL)
    return -EACCES;

  // Generate the required nonce
  uint8_t nonce[32];
  sgx_read_rand(nonce, 32);

  // sign the nonce
  sgx_ec256_signature_t signature;
  if (lauxus_sign_challenge(32, nonce, sk_u, &signature) < 0)
    return -1;

  // validate signature
  if (lauxus_validate_signature(32, nonce, user->pk_u, &signature) < 0)
    return -EACCES;

  FILE_SYSTEM->current_user = user;
  return 0;
}


int EMUL_EAPI sgx_add_user(const char *username, const sgx_ec256_public_t *pk_u, lauxus_uuid_t *u_uuid) {
  if (FILE_SYSTEM == NULL)
    return -EACCES;
  if (FILE_SYSTEM->current_user != NULL && !FILE_SYSTEM->current_user->is_root())
    return -EACCES;

  User *user = new User(username, pk_u);
  if (FILE_SYSTEM->supernode->add_user(user) == NULL)
    return -EEXIST;

  if (FILE_SYSTEM->e_write_meta_to_disk(FILE_SYSTEM->supernode) < 0)
    return -EPROTO;

  memcpy(u_uuid, user->u_uuid, sizeof(lauxus_uuid_t));
  return 0;
}

int EMUL_EAPI sgx_remove_user(const lauxus_uuid_t *u_uuid) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL || !FILE_SYSTEM->current_user->is_root())
    return -EACCES;

  User *removed = FILE_SYSTEM->supernode->remove_user_from_uuid(u_uuid);
  if (removed == NULL)
    return -EEXIST;

  if (FILE_SYSTEM->e_write_meta_to_disk(FILE_SYSTEM->supernode) < 0)
    goto err;

  delete removed;
  return 0;

err:
  delete removed;
  return -EPROTO;
}

int EMUL_EAPI sgx_edit_user_entitlement(const char *path, lauxus_right_t rights, const lauxus_uuid_t *u_uuid) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->edit_user_entitlement(path, rights, u_uuid);
}



/************************* Data Plane related ECALLS *************************/
int EMUL_EAPI sgx_get_user_entitlement(const char *path, lauxus_right_t *rights) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->get_rights(path, rights);
}


int EMUL_EAPI sgx_ls_buffer_size(const char *path) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;

  vector<string> files = FILE_SYSTEM->readdir(path);
  size_t size = 0;
  for (auto itr = files.begin(); itr != files.end(); itr++) {
    string name = (*itr);
    size += name.length() + 1;
  }
  return size;
}

int EMUL_EAPI sgx_readdir(const char *path, char separator, size_t buffer_size, char *buffer) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;

  vector<string> files = FILE_SYSTEM->readdir(path);
  size_t offset = 0, count_entries = 0;
  for (auto itr = files.begin(); itr != files.end() && offset < buffer_size; itr++, count_entries++) {
    string name = (*itr);
    memcpy(buffer+offset, (char*)name.c_str(), name.length());
    buffer[offset+name.length()] = separator;
    offset += name.length() + 1;
  }

  return count_entries;
}


int EMUL_EAPI sgx_entry_type(const char *path) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->entry_type(path);
}
int EMUL_EAPI sgx_get_times(const char *path, time_t *atime, time_t *mtime, time_t *ctime) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->get_times(path, atime, mtime, ctime);
}

int EMUL_EAPI sgx_rename(const char *old_path, const char *new_path) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->rename(old_path, new_path);
}


int EMUL_EAPI sgx_file_size(const char *filepath) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->file_size(filepath);
}

int EMUL_EAPI sgx_open_file(const char *filepath, lauxus_right_t asked_rights) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->open_file(filepath, asked_rights);
}
int EMUL_EAPI sgx_close_file(const char *filepath) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->close_file(filepath);
}

int EMUL_EAPI sgx_create_file(const char *reason, const char *filepath) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->create_file(reason, filepath);
}

int EMUL_EAPI sgx_read_file(const char *reason, const char *filepath, long offset, size_t buffer_size, uint8_t *buffer) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->read_file(reason, filepath, offset, buffer_size, buffer);
}

int EMUL_EAPI sgx_write_file(const char *reason, const char *filepath, long offset, size_t data_size, const uint8_t *data) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->write_file(reason, filepath, offset, data_size, data);
}

int EMUL_EAPI sgx_truncate_file(const char *filepath, long new_size) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->truncate_file(filepath, new_size);
}

int EMUL_EAPI sgx_unlink(const char *reason, const char *filepath) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->unlink(reason, filepath);
}


int EMUL_EAPI sgx_mkdir(const char *reason, const char *dirpath) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->create_directory(reason, dirpath);
}

int EMUL_EAPI sgx_rmdir(const char *reason, const char *dirpath) {
  if (FILE_SYSTEM == NULL || FILE_SYSTEM->current_user == NULL)
    return -EACCES;
  return FILE_SYSTEM->rm_directory(reason, dirpath);
}
