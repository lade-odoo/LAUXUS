#include "../utils/filesystem.hpp"
#include "../utils/encryption/aes_gcm.hpp"
#include "../utils/users/user.hpp"

#include "Enclave_t.h"
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include <cerrno>
#include <string>


static FileSystem* FILE_SYSTEM;



int sgx_init_new_filesystem(const char *supernode_path) {
  AES_GCM_context *root_key = new AES_GCM_context();
  AES_GCM_context *audit_root_key = new AES_GCM_context();
  Supernode *node = new Supernode(FileSystem::get_relative_path(supernode_path), root_key);
  FILE_SYSTEM = new FileSystem(root_key, audit_root_key, node, FileSystem::DEFAULT_BLOCK_SIZE);
  return 0;
}

void sgx_init_dumping_folders(const char *content_dir, const char* meta_dir, const char *audit_dir) {
  FILE_SYSTEM->init_dumping_folders(content_dir, meta_dir, audit_dir);
}

int sgx_init_existing_filesystem(const char *supernode_path, size_t rk_sealed_size, const char *sealed_rk,
                    size_t ark_sealed_size, const char *sealed_ark, size_t e_supernode_size, const char *e_supernode) {
  // allocating plain root keys
  uint32_t rk_plain_size = AES_GCM_context::size_without_mac();
  uint32_t ark_plain_size = AES_GCM_context::size_without_mac();
  uint8_t rk_plain[rk_plain_size], ark_plain[ark_plain_size];

  // unseal the rootkeys
  if (sgx_unseal_data((sgx_sealed_data_t*)sealed_rk, NULL, NULL, rk_plain, &rk_plain_size) != SGX_SUCCESS)
    return -EPROTO;
  if (sgx_unseal_data((sgx_sealed_data_t*)sealed_ark, NULL, NULL, ark_plain, &ark_plain_size) != SGX_SUCCESS)
    return -EPROTO;

  // Load the key and supernode content
  AES_GCM_context *root_key = new AES_GCM_context();
  if (root_key->load_without_mac(rk_plain_size, (char*)rk_plain) < 0)
    return -EPROTO;
  AES_GCM_context *audit_root_key = new AES_GCM_context();
  if (audit_root_key->load_without_mac(ark_plain_size, (char*)ark_plain) < 0)
    return -EPROTO;
  Supernode *node = new Supernode(FileSystem::get_relative_path(supernode_path), root_key);
  if (node->e_load(e_supernode_size, e_supernode) < 0)
    return -EPROTO;

  // Create the filesystem
  FILE_SYSTEM = new FileSystem(root_key, audit_root_key, node, FileSystem::DEFAULT_BLOCK_SIZE);
  return 0;
}

int sgx_destroy_filesystem(const char *rk_path, const char *ark_path, const char *supernode_path) {
  // buffer for root keys plaintext
  size_t rk_plain_size = AES_GCM_context::size_without_mac(); char plain_rk[rk_plain_size];
  size_t ark_plain_size = AES_GCM_context::size_without_mac(); char plain_ark[ark_plain_size];
  if (FILE_SYSTEM->root_key->dump_without_mac(rk_plain_size, plain_rk) < 0)
    return -EPROTO;
  if (FILE_SYSTEM->audit_root_key->dump_without_mac(ark_plain_size, plain_ark) < 0)
    return -EPROTO;

  // encrypting root keys
  size_t rk_seal_size = rk_plain_size + sizeof(sgx_sealed_data_t); char seal_rk[rk_seal_size];
  size_t ark_seal_size = ark_plain_size + sizeof(sgx_sealed_data_t); char seal_ark[ark_seal_size];
  sgx_status_t status = sgx_seal_data(0, NULL, rk_plain_size, (uint8_t*)plain_rk, rk_seal_size, (sgx_sealed_data_t*)seal_rk);
  if (status != SGX_SUCCESS)
    return -EPROTO;
  status = sgx_seal_data(0, NULL, ark_plain_size, (uint8_t*)plain_ark, ark_seal_size, (sgx_sealed_data_t*)seal_ark);
  if (status != SGX_SUCCESS)
    return -EPROTO;

  // buffer for encrypted supernode
  size_t e_supernode_size = FILE_SYSTEM->supernode->e_size(); char e_supernode[e_supernode_size];
  if (FILE_SYSTEM->supernode->e_dump(e_supernode_size, e_supernode) < 0)
    return -EPROTO;

  // saving the informations
  int ret;
  if (ocall_dump(&ret, rk_path, rk_seal_size, seal_rk) != SGX_SUCCESS || ret < 0)
    return -EPROTO;
  if (ocall_dump(&ret, ark_path, ark_seal_size, seal_ark) != SGX_SUCCESS || ret < 0)
    return -EPROTO;
  if (ocall_dump(&ret, supernode_path, e_supernode_size, e_supernode) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  delete FILE_SYSTEM;
  return 0;
}


int sgx_login(const char *sk_path, const char *user_uuid, size_t e_supernode_size, const char *e_supernode) {
  // check if the user exists
  User *user = FILE_SYSTEM->supernode->retrieve_user(user_uuid);
  if (user == NULL)
    return -EACCES;

  // Respond the required nonce
  uint8_t nonce[32];
  sgx_read_rand(nonce, 32);

  // Create the challenge
  size_t challenge_size = 32 + e_supernode_size;
  uint8_t challenge[challenge_size];
  std::memcpy(challenge, nonce, 32);
  std::memcpy(challenge+32, e_supernode, e_supernode_size);

  // ocall to sign challenge given nonce
  int ret;
  size_t sig_size = sizeof(sgx_ec256_signature_t); sgx_ec256_signature_t sig[sig_size];
  if (ocall_sign_challenge(&ret, sk_path, 32, (char*)nonce, sig_size, (char*)sig) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  // validate signature
  if (user->validate_signature(challenge_size, challenge, sig_size, sig) < 0)
    return -EACCES;

  FILE_SYSTEM->current_user = user;
  return 0;
}

int sgx_sign_message(size_t challenge_size, const char *challenge,
                    size_t sk_size, const char *sk, size_t sig_size, char *sig) {
  int ret = User::sign(challenge_size, (uint8_t*)challenge,
                    sk_size, (sgx_ec256_private_t*)sk,
                    sig_size, (sgx_ec256_signature_t*)sig);
  if (ret < 0)
    return -EPROTO;
  return 0;
}


int sgx_create_user(const char *username, const char *pk_path, const char *sk_path) {
  if (FILE_SYSTEM->current_user != NULL && !FILE_SYSTEM->current_user->is_root())
    return -EACCES;

  // allocating memory
  size_t pk_size = sizeof(sgx_ec256_public_t), sk_size = sizeof(sgx_ec256_private_t);
  char pk[pk_size], sk[sk_size];
  if (User::generate_keys(pk_size, (sgx_ec256_public_t*)pk, sk_size, (sgx_ec256_private_t*)sk) < 0)
    return -EPROTO;

  // creating user
  User *user = new User(username, pk_size, (sgx_ec256_public_t*)pk);
  if (FILE_SYSTEM->supernode->add_user(user) == NULL)
    return -EPROTO;

  // saving the user
  int ret;
  if (ocall_dump(&ret, pk_path, pk_size, pk) != SGX_SUCCESS || ret < 0)
    return -EPROTO;
  if (ocall_dump(&ret, sk_path, sk_size, sk) != SGX_SUCCESS || ret < 0)
    return -EPROTO;

  // set the current user if not yet one
  if (FILE_SYSTEM->current_user == NULL)
    FILE_SYSTEM->current_user = user;

  std::string msg = "New user successfully created with UUID: " + user->uuid + ".";
  ocall_print((char*)msg.c_str());
  return 0;
}

int sgx_add_user(const char *username, size_t pk_size, const char *pk) {
  if (FILE_SYSTEM->current_user == NULL)
    return -EPROTO;
  if (!FILE_SYSTEM->current_user->is_root())
    return -EACCES;

  User *user = new User(username, pk_size, (sgx_ec256_public_t*)pk);
  if (FILE_SYSTEM->supernode->add_user(user) == NULL)
    return -EEXIST;

  std::string msg = "New user successfully added with UUID: " + user->uuid + ".";
  ocall_print((char*)msg.c_str());
  return 0;
}

int sgx_remove_user(const char *user_uuid) {
  if (FILE_SYSTEM->current_user == NULL)
    return -EPROTO;
  if (!FILE_SYSTEM->current_user->is_root())
    return -EACCES;

  User *removed = FILE_SYSTEM->supernode->remove_user_from_uuid(user_uuid);
  if (removed == NULL)
    return -EEXIST;

  delete removed;
  return 0;
}


int sgx_edit_user_entitlement(const char *path, const unsigned char rights, const char* user_uuid) {
  return FILE_SYSTEM->edit_user_entitlement(path, rights, user_uuid);
}


int sgx_ls_buffer_size(const char *path) {
  std::vector<std::string> files = FILE_SYSTEM->readdir(path);
  size_t size = 0;

  for (auto itr = files.begin(); itr != files.end(); itr++) {
    std::string name = (*itr);
    size += name.length() + 1;
  }
  return size;
}

int sgx_readdir(const char *path, char separator, size_t buffer_size, char *buffer) {
  std::vector<std::string> files = FILE_SYSTEM->readdir(path);
  size_t offset = 0, count_entries = 0;

  for (auto itr = files.begin(); itr != files.end() && offset < buffer_size; itr++, count_entries++) {
    std::string name = (*itr);
    memcpy(buffer+offset, (char*)name.c_str(), name.length());
    buffer[offset+name.length()] = separator;
    offset += name.length() + 1;
  }

  return count_entries;
}


int sgx_entry_type(const char *path) {
  return FILE_SYSTEM->entry_type(path);
}
int sgx_get_rights(const char *path) {
  return FILE_SYSTEM->get_rights(path);
}

int sgx_file_size(const char *filepath) {
  return FILE_SYSTEM->file_size(filepath);
}
int sgx_create_file(const char *reason, const char *filepath) {
  return FILE_SYSTEM->create_file(reason, filepath);
}
int sgx_read_file(const char *reason, const char *filepath, long offset, size_t buffer_size, char *buffer) {
  return FILE_SYSTEM->read_file(reason, filepath, offset, buffer_size, buffer);
}
int sgx_write_file(const char *reason, const char *filepath, long offset, size_t data_size, const char *data) {
  return FILE_SYSTEM->write_file(reason, filepath, offset, data_size, data);
}
int sgx_unlink(const char *reason, const char *filepath) {
  return FILE_SYSTEM->unlink(reason, filepath);
}

int sgx_mkdir(const char *reason, const char *dirpath) {
  return FILE_SYSTEM->create_directory(reason, dirpath);
}
int sgx_rmdir(const char *reason, const char *dirpath) {
  return FILE_SYSTEM->rm_directory(reason, dirpath);
}
int sgx_opendir(const char *dirpath) {
  return FILE_SYSTEM->open_directory(dirpath);
}
