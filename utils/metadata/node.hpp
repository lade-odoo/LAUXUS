#ifndef __NODE_HPP__
#define __NODE_HPP__

#include "../../utils/encryption.hpp"
#include <string>
#include <vector>


class Node {
  public:
    std::string path;

    Node(const std::string &filename, AES_GCM_context *root_key);
    ~Node();

    size_t metadata_size();
    int dump_metadata(const size_t buffer_size, char *buffer);
    int load_metadata(Node *parent, const size_t buffer_size, const char *buffer);

    size_t preamble_size();
    int dump_preamble(const size_t buffer_size, char *buffer);
    int load_preamble(const size_t buffer_size, const char *buffer);

  private:
    AES_GCM_context *root_key;
    AES_GCM_context *aes_gcm_ctx;

  protected:
    virtual size_t size_sensitive() = 0;
    virtual int dump_sensitive(const size_t buffer_size, char *buffer) = 0;
    virtual int load_sensitive(Node *parent, const size_t buffer_size, const char *buffer) = 0;
};

#endif /*__NODE_HPP__*/
