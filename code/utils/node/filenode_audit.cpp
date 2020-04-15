#include "filenode_audit.hpp"
#include "../encryption/aes_gcm.hpp"

#include <string>
#include <cstring>



size_t FilenodeAudit::e_reason_size(const std::string &reason) {
  size_t mac_size = AES_GCM_context::size() - AES_GCM_context::size_without_mac();
  return sizeof(int) + mac_size + AES_GCM_context::size() + sizeof(int) + reason.length()+1;
}

int FilenodeAudit::e_reason_dump(AES_GCM_context *audit_root_key, const std::string &reason, const size_t buffer_size, char *buffer) {
  if (buffer_size < FilenodeAudit::e_reason_size(reason))
    return -1;

  int reason_length = reason.length()+1;
  size_t size_context = AES_GCM_context::size();
  size_t mac_size = AES_GCM_context::size() - AES_GCM_context::size_without_mac();


  // dumping the size of the reason
  size_t reason_size_offset = sizeof(int) + mac_size + size_context;
  std::memcpy(buffer+reason_size_offset, &reason_length, sizeof(int));

  // encrypting the reason with a newly created context
  AES_GCM_context *context = new AES_GCM_context();
  size_t e_reason_offset = reason_size_offset + sizeof(int);
  if (context->encrypt((uint8_t*)reason.c_str(), reason_length, NULL, 0, (uint8_t*)buffer+e_reason_offset) < 0)
    return -1;

  // encrypting the newly created context with the root key
  char b_context[size_context];
  if (context->dump(size_context, b_context) < 0)
    return -1;
  size_t e_context_offset = sizeof(int) + mac_size;
  if (audit_root_key->encrypt((uint8_t*)b_context, size_context, NULL, 0, (uint8_t*)buffer+e_context_offset) < 0)
    return -1;

  // dumping the mac generated from encrypting the new context
  size_t mac_offset = sizeof(int);
  std::memcpy(buffer+mac_offset, audit_root_key->p_mac, mac_size);

  int entry_size = mac_size + size_context + sizeof(int) + reason_length;
  std::memcpy(buffer, &entry_size, sizeof(int));

  // cleaning allocated objects
  delete context;

  return sizeof(int) + entry_size;
}

int FilenodeAudit::e_reason_entry_load(AES_GCM_context *audit_root_key, std::string &reason, const size_t buffer_size, const char *buffer) {
  // retrieve mac
  size_t mac_size = AES_GCM_context::size() - AES_GCM_context::size_without_mac();
  std::memcpy(audit_root_key->p_mac, buffer, mac_size);

  // retrieve crypto context
  AES_GCM_context *context = new AES_GCM_context();
  size_t e_crypto_offset = mac_size;
  int plain_size = AES_GCM_context::size(), cypher_size=AES_GCM_context::size();
  char plain[plain_size];
  int decrypted = audit_root_key->decrypt((uint8_t*)buffer+e_crypto_offset, cypher_size, NULL, 0, (uint8_t*)plain);
  if (decrypted != cypher_size)
    return -1;
  if (context->load(plain_size, plain) != decrypted)
    return -1;

  // retrieve length of reason
  int reason_length = 0;
  size_t reason_length_offset = e_crypto_offset + decrypted;
  std::memcpy(&reason_length, buffer+reason_length_offset, sizeof(int));

  // retrieve reason
  size_t e_reason_offset = reason_length_offset + sizeof(int);
  char b_reason[reason_length];
  int d_reason = context->decrypt((uint8_t*)buffer+e_reason_offset, reason_length, NULL, 0, (uint8_t*)b_reason);
  if (d_reason != reason_length)
    return -1;
  reason.resize(d_reason-1);
  std::memcpy(const_cast<char*>(reason.data()), b_reason, d_reason);

  delete context;

  return e_reason_offset + d_reason;
}
