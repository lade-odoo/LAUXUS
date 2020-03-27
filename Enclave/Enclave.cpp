#include <cerrno>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include "../utils/filesystem.hpp"
#include "../utils/encryption.hpp"


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
  if (rk_sealed_size != AES_GCM_context::size()+sizeof(sgx_sealed_data_t))
    return -1;

  // unseal the rootkey
  size_t plain_size = rk_sealed_size - sizeof(sgx_sealed_data_t);
  char plaintext[plain_size];
  sgx_status_t status = sgx_unseal_data((sgx_sealed_data_t*)sealed_rk, NULL, NULL, (uint8_t*)plaintext, (uint32_t*)&plain_size);
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
  pki_challenge_size = nonce_size+supernode_size; pki_challenge = (char*) malloc(pki_challenge_size);
  std::memcpy(pki_challenge, nonce, nonce_size);
  std::memcpy(pki_challenge+nonce_size, supernode, supernode_size);

  return 0;
}

int sgx_destroy_filesystem(size_t rk_sealed_size, char *sealed_rk,
                          size_t supernode_size, char* supernode) {
  if (rk_sealed_size != AES_GCM_context::size()+sizeof(sgx_sealed_data_t) ||
      supernode_size != FILE_SYSTEM->supernode->metadata_size())
    return -1;

  size_t plain_size = AES_GCM_context::size(); size_t seal_size = plain_size+sizeof(sgx_sealed_data_t);
  char plaintext[plain_size];
  FILE_SYSTEM->root_key->dump(plaintext);
  sgx_status_t status = sgx_seal_data(0, NULL, plain_size, (uint8_t*)plaintext, seal_size, (sgx_sealed_data_t*)sealed_rk);
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
  sgx_ecc_state_handle_t handle;
	sgx_status_t status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS)
    return -1;
	status = sgx_ecc256_create_key_pair((sgx_ec256_private_t*)sk, (sgx_ec256_public_t*)pk, handle);
  if (status != SGX_SUCCESS)
    return -1;
  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS)
    return -1;

  FILE_SYSTEM->user_id = FILE_SYSTEM->supernode->create_user(username, (sgx_ec256_public_t*)pk);
  return FILE_SYSTEM->user_id;
}

int sgx_add_user(const char *username, size_t pk_size, const char *pk) {
  if (FILE_SYSTEM->user_id != 0)
    return -1;
  FILE_SYSTEM->user_id = FILE_SYSTEM->supernode->create_user(username, (sgx_ec256_public_t*)pk);
  return FILE_SYSTEM->user_id;
}

int sgx_sign_message(size_t challenge_size, const char *challenge,
                    size_t sk_size, const char *sk,
                    size_t sig_size, char *sig) {
  sgx_ecc_state_handle_t handle;
  sgx_status_t status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS)
    return -1;
  status = sgx_ecdsa_sign((uint8_t*)challenge, challenge_size,
                    (sgx_ec256_private_t*)sk, (sgx_ec256_signature_t*)sig, handle);
  if (status != SGX_SUCCESS)
    return -1;
  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS)
    return -1;

  return 0;
}

int sgx_validate_signature(const char *username,
                          size_t sig_size, const char *sig,
                          size_t pk_size, const char *pk) {
  if (sig_size != sizeof(sgx_ec256_signature_t) || pk_size != sizeof(sgx_ec256_public_t))
    return -1;

  int user_id = FILE_SYSTEM->supernode->check_user(username, (sgx_ec256_public_t*)pk);
  if (user_id < 0)
    return -1;

  sgx_ecc_state_handle_t handle; uint8_t result;
  sgx_status_t status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS)
    return -1;
  status = sgx_ecdsa_verify((uint8_t*)pki_challenge, pki_challenge_size,
                  (sgx_ec256_public_t*)pk, (sgx_ec256_signature_t*)sig, &result, handle);
  if (status != SGX_SUCCESS || result == SGX_EC_INVALID_SIGNATURE)
    return -1;
  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS)
    return -1;

  free(pki_challenge);
  FILE_SYSTEM->user_id = user_id;
  return user_id;
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
