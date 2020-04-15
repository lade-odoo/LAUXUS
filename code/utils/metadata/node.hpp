#ifndef __NODE_HPP__
#define __NODE_HPP__

#include "../../utils/encryption/aes_gcm.hpp"

#include <string>
#include <vector>


class Node {
  public:
    std::string path;

    Node(const std::string &filename, AES_GCM_context *root_key);
    ~Node();

    static std::string generate_uuid();

    size_t e_size();
    int e_dump(const size_t buffer_size, char *buffer);
    int e_load(const size_t buffer_size, const char *buffer);

    bool equals(Node *other);

  private:
    AES_GCM_context *root_key;
    AES_GCM_context *aes_gcm_ctx;

    size_t p_preamble_size();
    int p_dump_preamble(const size_t buffer_size, char *buffer);
    int p_load_preamble(const size_t buffer_size, const char *buffer);

    size_t e_crypto_size();
    int e_dump_crypto(const size_t buffer_size, char *buffer);
    int e_load_crypto(const size_t buffer_size, const char *buffer);

    size_t e_sensitive_size();
    int e_dump_sensitive(const size_t buffer_size, char *buffer);
    int e_load_sensitive(const size_t buffer_size, const char *buffer);

  protected:
    virtual size_t p_sensitive_size() = 0;
    virtual int p_dump_sensitive(const size_t buffer_size, char *buffer) = 0;
    virtual int p_load_sensitive(const size_t buffer_size, const char *buffer) = 0;
};

#endif /*__NODE_HPP__*/
