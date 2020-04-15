#ifndef __METADATA_HPP__
#define __METADATA_HPP__

#include "encryption/aes_gcm.hpp"

#include <string>
#include <vector>


class Metadata {
  public:
    Metadata(AES_GCM_context *root_key);
    ~Metadata();

    size_t e_size();
    int e_dump(const size_t buffer_size, char *buffer);
    int e_load(const size_t buffer_size, const char *buffer);

    bool equals(Metadata *other);

  private:
    AES_GCM_context *root_key;
    AES_GCM_context *aes_gcm_ctx;

    size_t e_crypto_size();
    int e_dump_crypto(const size_t buffer_size, char *buffer);
    int e_load_crypto(const size_t buffer_size, const char *buffer);

    size_t e_sensitive_size();
    int e_dump_sensitive(const size_t buffer_size, char *buffer);
    int e_load_sensitive(const size_t buffer_size, const char *buffer);

  protected:
    virtual size_t p_preamble_size() = 0;
    virtual int p_dump_preamble(const size_t buffer_size, char *buffer) = 0;
    virtual int p_load_preamble(const size_t buffer_size, const char *buffer) = 0;

    virtual size_t p_sensitive_size() = 0;
    virtual int p_dump_sensitive(const size_t buffer_size, char *buffer) = 0;
    virtual int p_load_sensitive(const size_t buffer_size, const char *buffer) = 0;
};

#endif /*__METADATA_HPP__*/
