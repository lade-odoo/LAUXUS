#include "../../headers/nodes/node_audit.hpp"


NodeAudit::NodeAudit(string reason, lauxus_gcm_t *audit_root_key):Metadata::Metadata(audit_root_key) {
  this->reason = reason;
}
NodeAudit::NodeAudit(lauxus_gcm_t *audit_root_key):NodeAudit::NodeAudit("", audit_root_key) {}


size_t NodeAudit::p_preamble_size() { return 0; }
int NodeAudit::p_dump_preamble(const size_t buffer_size, uint8_t *buffer) { return 0; }
int NodeAudit::p_load_preamble(const size_t buffer_size, const uint8_t *buffer) { return 0; }


size_t NodeAudit::p_sensitive_size() {
  return sizeof(size_t) + this->reason.length()+1;
}

int NodeAudit::p_dump_sensitive(const size_t buffer_size, uint8_t *buffer) {
  if (buffer_size < this->p_sensitive_size())
    return -1;

  size_t written = 0;
  size_t reason_length = this->reason.length() + 1;
  memcpy(buffer+written, &reason_length, sizeof(size_t)); written += sizeof(size_t);
  memcpy(buffer+written, this->reason.c_str(), reason_length); written += reason_length;
  return written;
}

int NodeAudit::p_load_sensitive(const size_t buffer_size, const uint8_t *buffer) {
  if (buffer_size < sizeof(size_t))
    return -1;

  size_t read = 0; size_t reason_length = 0;
  memcpy(&reason_length, buffer+read, sizeof(size_t)); read += sizeof(size_t);
  if (buffer_size-read < reason_length)
    return -1;

  this->reason.resize(reason_length-1);
  memcpy(const_cast<char*>(this->reason.data()), buffer+read, reason_length); read += reason_length;
  return read;
}
