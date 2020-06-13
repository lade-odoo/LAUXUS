#ifndef __FILENODE_HPP__
#define __FILENODE_HPP__

#include "node.hpp"
#include "filenode_content.hpp"
#include "../encryption/aes_ctr.hpp"
#include "../encryption/aes_gcm.hpp"

#include <string>
#include <map>

using namespace std;



class Filenode: public Node {
  public:
    FilenodeContent *content;
    Filenode(const string &relative_path, lauxus_gcm_t *root_key, size_t block_size);
    Filenode(lauxus_gcm_t *root_key, size_t block_size);
    ~Filenode();

    bool equals(Filenode *other);

    int truncate_keys(size_t new_size);

  private:
    map<size_t, lauxus_ctr_t*> *aes_ctr_ctxs; // block_index - key

  protected:
    size_t p_preamble_size();
    int p_dump_preamble(const size_t buffer_size, uint8_t *buffer);
    int p_load_preamble(const size_t buffer_size, const uint8_t *buffer);

    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, uint8_t *buffer);
    int p_load_sensitive(const size_t buffer_size, const uint8_t *buffer);
};

#endif /*__FILENODE_HPP__*/
