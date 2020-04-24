#ifndef __FILENODE_HPP__
#define __FILENODE_HPP__

#include "../encryption/aes_gcm.hpp"
#include "node.hpp"
#include "filenode_content.hpp"

#include <string>
#include <map>



class Filenode: public Node {
  public:
    FilenodeContent *content;
    Filenode(const std::string &uuid, const std::string &relative_path, AES_GCM_context *root_key, size_t block_size);
    Filenode(const std::string &uuid, AES_GCM_context *root_key, size_t block_size);
    ~Filenode();

    bool equals(Filenode *other);

  private:
    std::map<size_t, AES_CTR_context*> *aes_ctr_ctxs;

  protected:
    size_t p_preamble_size();
    int p_dump_preamble(const size_t buffer_size, char *buffer);
    int p_load_preamble(const size_t buffer_size, const char *buffer);
    
    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, char *buffer);
    int p_load_sensitive(const size_t buffer_size, const char *buffer);
};

#endif /*__FILENODE_HPP__*/
