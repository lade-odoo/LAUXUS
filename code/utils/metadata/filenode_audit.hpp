#ifndef __FILENODE_AUDIT_HPP__
#define __FILENODE_AUDIT_HPP__

#include "../../utils/encryption/aes_gcm.hpp"

#include <string>



class FilenodeAudit {
  public:
    static size_t e_reason_size(const std::string &reason);
    static int e_reason_dump(AES_GCM_context *audit_root_key, const std::string &reason, const size_t buffer_size, char *buffer);
    static int e_reason_entry_load(AES_GCM_context *audit_root_key, std::string &reason, const size_t buffer_size, const char *buffer);
};

#endif /*__FILENODE_AUDIT_HPP__*/
