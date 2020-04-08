#ifndef __FILENODE_AUDIT_HPP__
#define __FILENODE_AUDIT_HPP__

#include "../../utils/encryption.hpp"

#include <string>



class FilenodeAudit {
  public:
    static int e_reason_size(const std::string &reason);
    static int e_reason_dump(AES_GCM_context *audit_root_key, const std::string &reason, const size_t buffer_size, char *buffer);
};

#endif /*__FILENODE_AUDIT_HPP__*/
