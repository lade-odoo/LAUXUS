#ifndef __DIRNODE_HPP__
#define __DIRNODE_HPP__

#include "../users/user.hpp"
#include "../encryption/aes_gcm.hpp"
#include "node.hpp"

#include <string>

using namespace std;



class Dirnode: public Node {
  public:
    Dirnode(const string &uuid, AES_GCM_context *root_key);
    Dirnode(const string &uuid, const std::string &relative_path, AES_GCM_context *root_key);
};

#endif /*__DIRNODE_HPP__*/
