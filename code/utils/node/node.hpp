#ifndef __NODE_HPP__
#define __NODE_HPP__

#include "../metadata.hpp"
#include "../encryption/aes_gcm.hpp"

#include <string>

using namespace std;


class Node: public Metadata {
  public:
    string path, uuid;

    Node(const string &uuid, const string &path, AES_GCM_context *root_key);
    Node(const string &uuid, AES_GCM_context *root_key);
    ~Node();

    bool equals(Node *other);

    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, char *buffer);
    int p_load_sensitive(const size_t buffer_size, const char *buffer);

    // Static functions
    static string generate_uuid();
};

#endif /*__NODE_HPP__*/
