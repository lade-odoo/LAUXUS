#ifndef __SUPERNODE_HPP__
#define __SUPERNODE_HPP__

#include "../../utils/metadata/node.hpp"
#include "sgx_tcrypto.h"
#include <string>
#include <map>



class Supernode: public Node {
  public:
    Supernode(const std::string &filename, AES_GCM_context *root_key);
    ~Supernode();

    int create_user(const std::string &username, sgx_ec256_public_t *p_public);
    int check_user(const std::string &username, sgx_ec256_public_t *p_public);

  private:
    std::map<int, std::pair<std::string, sgx_ec256_public_t*>> *allowed_users;

  protected:
    size_t size_sensitive();
    int dump_sensitive(char *buffer);
    int load_sensitive(const size_t buffer_size, const char *buffer);
};

#endif /*__SUPERNODE_HPP__*/
