#ifndef __NODE_HPP__
#define __NODE_HPP__

#include "../metadata.hpp"
#include "../encryption/aes_gcm.hpp"

#include <string>

using namespace std;


class Node: public Metadata {
  public:
    string path;

    Node(const string &path, AES_GCM_context *root_key);
    ~Node();

    static string generate_uuid();
};

#endif /*__NODE_HPP__*/
