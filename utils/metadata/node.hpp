#ifndef __NODE_HPP__
#define __NODE_HPP__

#include "../../utils/encryption.hpp"
#include <string>
#include <vector>


class Node {
  public:
    std::string filename;

    Node(const std::string &filename);
    ~Node();

    size_t metadata_size();
    int dump_metadata(const size_t buffer_size, char *buffer);
    int load_metadata(const size_t buffer_size, const char *buffer);

  private:
    AES_GCM_context *aes_gcm_ctx;

  protected:
    virtual size_t size_sensitive() = 0;
    virtual int dump_sensitive(char *buffer) = 0;
    virtual int load_sensitive(const size_t buffer_size, const char *buffer) = 0;

    virtual size_t size_aad() = 0;
    virtual int dump_aad(char *buffer) = 0;
};

#endif /*__NODE_HPP__*/
