#include <cerrno>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include "../utils/filesystem.hpp"
#include "../utils/encryption.hpp"
#include "../utils/users/user.hpp"


static FileSystem* FILE_SYSTEM;
size_t pki_challenge_size; char *pki_challenge;


int sgx_init_new_filesystem(const char *supernode_path) {
  AES_GCM_context *root_key = new AES_GCM_context();
  Supernode *node = new Supernode(supernode_path, root_key);
  FILE_SYSTEM = new FileSystem(root_key, node, FileSystem::DEFAULT_BLOCK_SIZE);
  return 0;
}

int sgx_init_existing_filesystem(const char *supernode_path,
                                size_t rk_sealed_size, const char *sealed_rk,
                                size_t supernode_size, const char *supernode,
                                size_t nonce_size, char *nonce) {
  size_t plain_size = AES_GCM_context::size();
  size_t seal_size = plain_size + sizeof(sgx_sealed_data_t);
  char plaintext[plain_size];

  if (rk_sealed_size != seal_size)
    return -1;

  // unseal the rootkey
  sgx_status_t status = sgx_unseal_data((sgx_sealed_data_t*)sealed_rk, NULL,
                            NULL, (uint8_t*)plaintext, (uint32_t*)&plain_size);
  if (status != SGX_SUCCESS)
    return -1;

  // Create the file system
  AES_GCM_context *root_key = new AES_GCM_context();
  Supernode *node = new Supernode(supernode_path, root_key);
  if (root_key->load(plaintext) < 0 || node->load_metadata(supernode_size, supernode) < 0)
    return -1;
  FILE_SYSTEM = new FileSystem(root_key, node, FileSystem::DEFAULT_BLOCK_SIZE);

  // Respond the required nonce
  char nonce_char = 0x11;
  for (int i=0; i < nonce_size; i++)
    std::memcpy(nonce+i, &nonce_char, 1);

  // Create the challenge
  pki_challenge_size = nonce_size + supernode_size;
  pki_challenge = (char*) malloc(pki_challenge_size);
  std::memcpy(pki_challenge, nonce, nonce_size);
  std::memcpy(pki_challenge+nonce_size, supernode, supernode_size);

  return 0;
}

int sgx_destroy_filesystem(size_t rk_sealed_size, char *sealed_rk,
                          size_t supernode_size, char* supernode) {
  size_t plain_size = AES_GCM_context::size();
  size_t seal_size = plain_size + sizeof(sgx_sealed_data_t);
  size_t meta_size = FILE_SYSTEM->supernode->metadata_size();
  char plaintext[plain_size];

  if (rk_sealed_size != seal_size || supernode_size != meta_size)
    return -1;

  if (FILE_SYSTEM->root_key->dump(plaintext) < 0)
    return -1;

  sgx_status_t status = sgx_seal_data(0, NULL, plain_size, (uint8_t*)plaintext,
                                      seal_size, (sgx_sealed_data_t*)sealed_rk);
  if (status != SGX_SUCCESS)
    return -1;

  if (FILE_SYSTEM->supernode->dump_metadata(supernode_size, supernode) < 0)
    return -1;

  delete FILE_SYSTEM;
  return 0;
}


int sgx_supernode_size() {
  return FILE_SYSTEM->supernode->metadata_size();
}

int sgx_create_user(const char *username,
                    size_t pk_size, char *pk,
                    size_t sk_size, char *sk) {
  if (User::generate_keys(pk_size, (sgx_ec256_public_t*)pk, sk_size, (sgx_ec256_private_t*)sk) < 0)
    return -1;

  User *user = new User(username, pk_size, (sgx_ec256_public_t*)pk);
  FILE_SYSTEM->current_user = FILE_SYSTEM->supernode->add_user(user);
  return FILE_SYSTEM->current_user->id;
}

int sgx_add_user(const char *username, size_t pk_size, const char *pk) {
  if (FILE_SYSTEM->current_user == NULL || !FILE_SYSTEM->current_user->is_root())
    return -1;

  User *user = new User(username, pk_size, (sgx_ec256_public_t*)pk);
  if (FILE_SYSTEM->supernode->add_user(user) < 0)
    return -1;
  return FILE_SYSTEM->current_user->id;
}

int sgx_sign_message(size_t challenge_size, const char *challenge,
                    size_t sk_size, const char *sk,
                    size_t sig_size, char *sig) {
  return User::sign(challenge_size, (uint8_t*)challenge,
                    sk_size, (sgx_ec256_private_t*)sk,
                    sig_size, (sgx_ec256_signature_t*)sig);
}

int sgx_validate_signature(const char *username,
                          size_t sig_size, const char *sig,
                          size_t pk_size, const char *pk) {
  User *tmp_user = new User(username, pk_size, (sgx_ec256_public_t*)pk);
  User *user = FILE_SYSTEM->supernode->check_user(tmp_user);
  delete tmp_user;
  if (user == NULL)
    return -1;

  if (user->validate_signature(pki_challenge_size, (uint8_t*)pki_challenge, sig_size, (sgx_ec256_signature_t*)sig) < 0)
    return -2;

  free(pki_challenge);
  pki_challenge = NULL;
  FILE_SYSTEM->current_user = user;
  return user->id;
}


int sgx_ls_buffer_size() {
  std::vector<std::string> files = FILE_SYSTEM->readdir();
  size_t size = 0;

  for (auto itr = files.begin(); itr != files.end(); itr++) {
    std::string name = (*itr);
    size += name.length() + 1;
  }
  return size;
}

int sgx_readdir(char separator, size_t buffer_size, char *buffer) {
  std::vector<std::string> files = FILE_SYSTEM->readdir();
  size_t offset = 0, count_entries = 0;

  for (auto itr = files.begin(); itr != files.end() && offset < buffer_size; itr++, count_entries++) {
    std::string name = (*itr);
    memcpy(buffer+offset, (char*)name.c_str(), name.length());
    buffer[offset+name.length()] = separator;
    offset += name.length() + 1;
  }

  return count_entries;
}


int sgx_isfile(const char *filename) {
  if (FILE_SYSTEM->isfile(filename))
    return EEXIST;
  return -ENOENT;
}

int sgx_file_size(const char *filename) {
  return FILE_SYSTEM->file_size(filename);
}

int sgx_create_file(const char *filename) {
  return FILE_SYSTEM->create_file(filename);
}

int sgx_read_file(const char *filename, long offset, size_t buffer_size, char *buffer) {
  return FILE_SYSTEM->read_file(filename, offset, buffer_size, buffer);
}

int sgx_write_file(const char *filename, long offset, size_t data_size, const char *data) {
  return FILE_SYSTEM->write_file(filename, offset, data_size, data);
}

int sgx_unlink(const char *filename) {
  return FILE_SYSTEM->unlink(filename);
}


int sgx_metadata_size(const char *filename) {
  return FILE_SYSTEM->metadata_size(filename);
}

int sgx_dump_metadata(const char *filename, size_t buffer_size, char *buffer) {
  return FILE_SYSTEM->dump_metadata(filename, buffer_size, buffer);
}

int sgx_load_metadata(const char *filename, size_t buffer_size, const char *buffer) {
  return FILE_SYSTEM->load_metadata(filename, buffer_size, buffer);
}


int sgx_encryption_size(const char *filename, long up_offset, size_t up_size) {
  return FILE_SYSTEM->encryption_size(filename, up_offset, up_size);
}

int sgx_dump_encryption(const char *filename, long up_offset, size_t up_size, size_t buffer_size, char *buffer) {
  return FILE_SYSTEM->dump_encryption(filename, up_offset, up_size, buffer_size, buffer);
}

int sgx_load_encryption(const char *filename, long offset, size_t buffer_size, const char *buffer) {
  return FILE_SYSTEM->load_encryption(filename, offset, buffer_size, buffer);
}
