#ifndef __METADATA_HPP__
#define __METADATA_HPP__

#include "../../../../flag.h"
#if EMULATING
#   include "../../../../tests/SGX_Emulator/sgx_trts.hpp"
#else
#   include "sgx_trts.h"
#endif

#include "aes_gcm.hpp"

#include <string>
#include <cstring>
#include <vector>

using namespace std;



class Metadata {
  public:
    Metadata(lauxus_gcm_t *root_key);
    ~Metadata();

    size_t e_size();
    int e_dump(const size_t buffer_size, uint8_t *buffer);
    int e_load(const size_t buffer_size, const uint8_t *buffer);

    bool equals(Metadata *other);
    void update_crypto_ctx();

  private:
    lauxus_gcm_t *root_key;
    lauxus_gcm_t *aes_gcm_ctx;

    size_t e_crypto_size();
    int e_dump_crypto(const size_t buffer_size, uint8_t *buffer);
    int e_load_crypto(const size_t buffer_size, const uint8_t *buffer);

    size_t e_sensitive_size();
    int e_dump_sensitive(const size_t buffer_size, uint8_t *buffer);
    int e_load_sensitive(const size_t buffer_size, const uint8_t *buffer);

  protected:
    virtual size_t p_preamble_size() = 0;
    virtual int p_dump_preamble(const size_t buffer_size, uint8_t *buffer) = 0;
    virtual int p_load_preamble(const size_t buffer_size, const uint8_t *buffer) = 0;

    virtual size_t p_sensitive_size() = 0;
    virtual int p_dump_sensitive(const size_t buffer_size, uint8_t *buffer) = 0;
    virtual int p_load_sensitive(const size_t buffer_size, const uint8_t *buffer) = 0;
};

#endif /*__METADATA_HPP__*/
