#ifndef __SUPERNODE_HPP__
#define __SUPERNODE_HPP__

#include "../../utils/users/user.hpp"
#include "../../utils/metadata/node.hpp"
#include "sgx_tcrypto.h"
#include <string>
#include <map>



class Supernode: public Node {
  public:
    Supernode(const std::string &filename, AES_GCM_context *root_key);
    ~Supernode();

    User *root_user();

    User *add_user(User *user);
    User *check_user(User *user);
    User *retrieve_user(int user_id);

  private:
    std::map<int, User*> *allowed_users;

  protected:
    size_t size_sensitive();
    int dump_sensitive(const size_t buffer_size, char *buffer);
    int load_sensitive(Node *parent, const size_t buffer_size, const char *buffer);
};

#endif /*__SUPERNODE_HPP__*/
