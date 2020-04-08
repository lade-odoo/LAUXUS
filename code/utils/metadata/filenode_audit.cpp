#include "../../utils/metadata/filenode_audit.hpp"
#include "../../utils/encryption.hpp"

#include <string>



int FilenodeAudit::e_reason_size(const std::string &reason) {
  size_t mac_size = AES_GCM_context::size() - AES_GCM_context::size_without_mac();
  return mac_size + AES_GCM_context::size() + sizeof(int) + reason.length()+1;
}

int FilenodeAudit::e_reason_dump(AES_GCM_context *audit_root_key, const std::string &reason, const size_t buffer_size, char *buffer) {
  if (buffer_size < this->e_reason_size(reason))
    return -1;

  int reason_length = reason.length()+1;
  size_t size_context = AES_GCM_context::size();
  size_t mac_size = AES_GCM_context::size() - AES_GCM_context::size_without_mac();


  // dumping the size of the reason
  size_t reason_size_offset = mac_size + size_context;
  std::memcpy(buffer+reason_size_offset, reason_length, sizeof(int));

  // encrypting the reason with a newly created context
  AES_GCM_context *context = new AES_GCM_context();
  size_t e_reason_offset = mac_size + size_context + sizeof(int);
  if (context->encrypt((uint8_t*)reason.c_str(), , NULL, 0, buffer+e_reason_offset) < 0)
    return -1;

  // encrypting the newly created context with the root key
  char b_context[size_context];
  if (context->dump(size_context, b_context) < 0)
    return -1;
  if (audit_root_key->encrypt(b_context, size_context, NULL, 0, buffer+mac_size) < 0)
    return -1;

  // dumping the mac generated from encrypting the new context
  std::memcpy(buffer, audit_root_key->p_mac, mac_size);

  // cleaning allocated objects
  delete context;

  return mac_size + size_context + sizeof(int) + reason_length;
}
