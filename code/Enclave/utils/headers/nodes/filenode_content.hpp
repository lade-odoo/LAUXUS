#ifndef __FILENODE_CONTENT_HPP__
#define __FILENODE_CONTENT_HPP__

#include "../encryption/aes_ctr.hpp"

#include <string>
#include <vector>
#include <map>

using namespace std;



class FilenodeContent {
  public:
    size_t size = 0;

    FilenodeContent(size_t block_size, map<size_t, lauxus_ctr_t*> *aes_ctr_ctxs);
    ~FilenodeContent();

    void free_loaded();

    int read(const long offset, const size_t buffer_size, uint8_t *buffer);
    int write(const long offset, const size_t data_size, const uint8_t *data);

    int e_size(const long up_offset, const size_t up_size);
    int e_dump(const long up_offset, const size_t up_size, const size_t buffer_size, uint8_t *buffer);
    int e_load(const long up_offset, const size_t up_size, const size_t buffer_size, const uint8_t *buffer);

    // Static functions
    static map<string, size_t> block_required(const size_t block_size, const long offset, const size_t length);

  private:
    size_t block_size;
    map<size_t, vector<uint8_t>> *plain, *cipher;
    map<size_t, lauxus_ctr_t*> *aes_ctr_ctxs;

    int encrypt_block(const size_t block_index);
    int decrypt_block(const size_t block_index);
};

#endif /*__FILENODE_CONTENT_HPP__*/
