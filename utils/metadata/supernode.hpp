#ifndef __SUPERNODE_HPP__
#define __SUPERNODE_HPP__

#include "../../utils/users/user.hpp"
#include "../../utils/encryption.hpp"
#include "../../utils/metadata/node.hpp"

#include <string>
#include <map>



class Supernode: public Node {
  public:
    Supernode(const std::string &filename, AES_GCM_context *root_key);
    ~Supernode();

    User *add_user(User *user);
    User *remove_user(User *user);
    User *check_user(User *user);
    User *retrieve_user(int user_id);

    bool equals(Supernode *other);

  private:
    std::map<int, User*> *allowed_users;

  protected:
    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, char *buffer);
    int p_load_sensitive(Node *parent, const size_t buffer_size, const char *buffer);
};

#endif /*__SUPERNODE_HPP__*/
