#ifndef __DIRNODE_HPP__
#define __DIRNODE_HPP__

#include "node.hpp"
#include "../encryption/aes_gcm.hpp"

#include <string>

using namespace std;



class Dirnode: public Node {
  public:
    Dirnode(lauxus_gcm_t *root_key);
    Dirnode(const string &relative_path, lauxus_gcm_t *root_key);
};

#endif /*__DIRNODE_HPP__*/
