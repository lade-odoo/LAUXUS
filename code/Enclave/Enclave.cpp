#include "../utils/filesystem.hpp"
#include "../utils/encryption.hpp"
#include "../utils/users/user.hpp"
#include "../utils/metadata/filenode_audit.hpp"

#include "sgx_tseal.h"
#include "Enclave_t.h"

#include <cerrno>


static FileSystem* FILE_SYSTEM;
size_t pki_challenge_size; char *pki_challenge;


int sgx_init_new_filesystem(const char *supernode_path) {
  AES_GCM_context *root_key = new AES_GCM_context();
  AES_GCM_context *audit_root_key = new AES_GCM_context();
  Supernode *node = new Supernode(supernode_path, root_key);
  FILE_SYSTEM = new FileSystem(root_key, audit_root_key, node, FileSystem::DEFAULT_BLOCK_SIZE);
  return 0;
}

int sgx_init_existing_filesystem(const char *supernode_path,
                                size_t rk_sealed_size, const char *sealed_rk,
                                size_t ark_sealed_size, const char *sealed_ark,
                                size_t supernode_size, const char *supernode,
                                size_t nonce_size, char *nonce) {
  size_t rk_plain_size = AES_GCM_context::size_without_mac();
  size_t ark_plain_size = AES_GCM_context::size_without_mac();
  char rk_plaintext[rk_plain_size], ark_plaintext[ark_plain_size];

  if (rk_sealed_size != rk_plain_size+sizeof(sgx_sealed_data_t) || ark_sealed_size != ark_plain_size+sizeof(sgx_sealed_data_t))
    return -EPROTO;

  // unseal the rootkey
  sgx_status_t status = sgx_unseal_data((sgx_sealed_data_t*)sealed_rk, NULL,
                            NULL, (uint8_t*)rk_plaintext, (uint32_t*)&rk_plain_size);
  if (status != SGX_SUCCESS)
    return -EPROTO;
  status = sgx_unseal_data((sgx_sealed_data_t*)sealed_ark, NULL,
                NULL, (uint8_t*)ark_plaintext, (uint32_t*)&ark_plain_size);
  if (status != SGX_SUCCESS)
    return -EPROTO;

  // Create the file system
  AES_GCM_context *root_key = new AES_GCM_context();
  AES_GCM_context *audit_root_key = new AES_GCM_context();
  Supernode *node = new Supernode(supernode_path, root_key);
  if (root_key->load_without_mac(rk_plain_size, rk_plaintext) < 0 ||
        audit_root_key->load_without_mac(ark_plain_size, ark_plaintext) < 0 ||
        node->e_load(supernode_size, supernode) < 0)
    return -EPROTO;
  FILE_SYSTEM = new FileSystem(root_key, audit_root_key, node, FileSystem::DEFAULT_BLOCK_SIZE);

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
                          size_t ark_sealed_size, char *sealed_ark,
                          size_t supernode_size, char* supernode) {
  size_t rk_plain_size = AES_GCM_context::size_without_mac();
  size_t ark_plain_size = AES_GCM_context::size_without_mac();
  size_t rk_seal_size = rk_plain_size + sizeof(sgx_sealed_data_t);
  size_t ark_seal_size = ark_plain_size + sizeof(sgx_sealed_data_t);
  char rk_plaintext[rk_plain_size];
  char ark_plaintext[ark_plain_size];

  if (rk_sealed_size != rk_seal_size || ark_sealed_size != ark_seal_size || supernode_size != FILE_SYSTEM->supernode->e_size())
    return -EPROTO;

  if (FILE_SYSTEM->root_key->dump_without_mac(rk_plain_size, rk_plaintext) < 0)
    return -EPROTO;
  if (FILE_SYSTEM->audit_root_key->dump_without_mac(ark_plain_size, ark_plaintext) < 0)
    return -EPROTO;

  sgx_status_t status = sgx_seal_data(0, NULL, rk_plain_size, (uint8_t*)rk_plaintext,
                                      rk_seal_size, (sgx_sealed_data_t*)sealed_rk);
  if (status != SGX_SUCCESS)
    return -EPROTO;
  status = sgx_seal_data(0, NULL, ark_plain_size, (uint8_t*)ark_plaintext,
                          ark_seal_size, (sgx_sealed_data_t*)sealed_ark);
  if (status != SGX_SUCCESS)
    return -EPROTO;

  if (FILE_SYSTEM->supernode->e_dump(supernode_size, supernode) < 0)
    return -EPROTO;

  delete FILE_SYSTEM;
  return 0;
}


int sgx_supernode_e_size() {
  return FILE_SYSTEM->supernode->e_size();
}


int sgx_create_user(const char *username, size_t pk_size, char *pk,
                      size_t sk_size, char *sk) {
  if (FILE_SYSTEM->current_user != NULL)
    return -EPROTO;
  if (User::generate_keys(pk_size, (sgx_ec256_public_t*)pk, sk_size, (sgx_ec256_private_t*)sk) < 0)
    return -EPROTO;

  User *user = new User(username, pk_size, (sgx_ec256_public_t*)pk);

  FILE_SYSTEM->current_user = FILE_SYSTEM->supernode->add_user(user);
  if (FILE_SYSTEM->current_user == NULL)
    return -EPROTO;
  return FILE_SYSTEM->current_user->id;
}

int sgx_add_user(const char *username, size_t pk_size, const char *pk) {
  if (FILE_SYSTEM->current_user == NULL)
    return -EPROTO;
  if (!FILE_SYSTEM->current_user->is_root())
    return -EACCES;

  User *user = new User(username, pk_size, (sgx_ec256_public_t*)pk);
  if (FILE_SYSTEM->supernode->add_user(user) == NULL)
    return -EEXIST;
  return FILE_SYSTEM->current_user->id;
}

int sgx_remove_user(const char *username, size_t pk_size, const char *pk) {
  if (FILE_SYSTEM->current_user == NULL)
    return -EPROTO;
  if (!FILE_SYSTEM->current_user->is_root())
    return -EACCES;

  User *user = new User(username, pk_size, (sgx_ec256_public_t*)pk);
  if (FILE_SYSTEM->supernode->remove_user(user) == NULL)
    return -EEXIST;
  return FILE_SYSTEM->current_user->id;
}


int sgx_sign_message(size_t challenge_size, const char *challenge,
                    size_t sk_size, const char *sk,
                    size_t sig_size, char *sig) {
  int ret = User::sign(challenge_size, (uint8_t*)challenge,
                    sk_size, (sgx_ec256_private_t*)sk,
                    sig_size, (sgx_ec256_signature_t*)sig);
  if (ret < 0)
    return -EPROTO;
  return 0;
}

int sgx_validate_signature(const int user_id,
                          size_t sig_size, const char *sig) {
  User *user = FILE_SYSTEM->supernode->retrieve_user(user_id);
  if (user == NULL)
    return -EACCES;

  if (user->validate_signature(pki_challenge_size, (uint8_t*)pki_challenge, sig_size, (sgx_ec256_signature_t*)sig) < 0)
    return -EACCES;

  free(pki_challenge);
  pki_challenge = NULL;
  FILE_SYSTEM->current_user = user;
  return 0;
}


int sgx_edit_user_policy(const char *filename, const unsigned char policy, const int user_id) {
  return FILE_SYSTEM->edit_user_policy(filename, policy, user_id);
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


int sgx_get_uuid(const char *filename, size_t buffer_size, char *buffer) {
  return FILE_SYSTEM->get_uuid(filename, buffer_size, buffer);
}

int sgx_e_reason_size(const char *reason) {
  return FilenodeAudit::e_reason_size(reason);
}


int sgx_isfile(const char *filename) {
  if (FILE_SYSTEM->isfile(filename))
    return EEXIST;
  return -ENOENT;
}

int sgx_file_size(const char *filename) {
  return FILE_SYSTEM->file_size(filename);
}

int sgx_getattr(const char *filename) {
  return FILE_SYSTEM->getattr(filename);
}

int sgx_create_file(const char *filename, const char *reason, size_t e_reason_b_size, char *e_reason_b) {
  return FILE_SYSTEM->create_file(filename, reason, e_reason_b_size, e_reason_b);
}

int sgx_read_file(const char *filename,
                  const char *reason, size_t e_reason_b_size, char *e_reason_b,
                  long offset, size_t buffer_size, char *buffer) {
  return FILE_SYSTEM->read_file(filename, reason, e_reason_b_size, e_reason_b, offset, buffer_size, buffer);
}

int sgx_write_file(const char *filename,
                    const char *reason, size_t e_reason_b_size, char *e_reason_b,
                    long offset, size_t data_size, const char *data) {
  return FILE_SYSTEM->write_file(filename, reason, e_reason_b_size, e_reason_b, offset, data_size, data);
}

int sgx_unlink(const char *filename) {
  return FILE_SYSTEM->unlink(filename);
}


int sgx_e_metadata_size(const char *filename) {
  return FILE_SYSTEM->e_metadata_size(filename);
}

int sgx_e_dump_metadata(const char *filename, size_t buffer_size, char *buffer) {
  return FILE_SYSTEM->e_dump_metadata(filename, buffer_size, buffer);
}

int sgx_e_load_metadata(const char *uuid, size_t buffer_size, const char *buffer) {
  return FILE_SYSTEM->e_load_metadata(uuid, buffer_size, buffer);
}


int sgx_e_file_size(const char *filename, long up_offset, size_t up_size) {
  return FILE_SYSTEM->e_file_size(filename, up_offset, up_size);
}

int sgx_e_dump_file(const char *filename, long up_offset, size_t up_size, size_t buffer_size, char *buffer) {
  return FILE_SYSTEM->e_dump_file(filename, up_offset, up_size, buffer_size, buffer);
}

int sgx_e_load_file(const char *uuid, long offset, size_t buffer_size, const char *buffer) {
  return FILE_SYSTEM->e_load_file(uuid, offset, buffer_size, buffer);
}
