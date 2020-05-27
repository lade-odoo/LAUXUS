#ifndef __NODE_AUDIT_HPP__
#define __NODE_AUDIT_HPP__

#include "../encryption/aes_gcm.hpp"
#include "../encryption/metadata.hpp"

#include <string>

using namespace std;


class NodeAudit: public Metadata {
  public:
    NodeAudit(string reason, lauxus_gcm_t *audit_root_key);
    NodeAudit(lauxus_gcm_t *audit_root_key);

  private:
    string reason;

  protected:
    size_t p_preamble_size();
    int p_dump_preamble(const size_t buffer_size, uint8_t *buffer);
    int p_load_preamble(const size_t buffer_size, const uint8_t *buffer);

    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, uint8_t *buffer);
    int p_load_sensitive(const size_t buffer_size, const uint8_t *buffer);
};

#endif /*__NODE_AUDIT_HPP__*/
