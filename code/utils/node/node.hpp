#ifndef __NODE_HPP__
#define __NODE_HPP__

#include "../metadata.hpp"
#include "../encryption/aes_gcm.hpp"

#include <string>
#include <map>

using namespace std;


class Node: public Metadata {
  public:
    static const size_t UUID_SIZE = 21;
    string relative_path, uuid;

    Node(const string &uuid, const string &relative_path, AES_GCM_context *root_key);
    Node(const string &uuid, AES_GCM_context *root_key);
    ~Node();

    bool equals(Node *other);

    bool is_correct_node(string parent_path);
    Node* retrieve_node(string relative_path);
    int add_node_entry(Node *node);
    int link_node_entry(string uuid, Node *node);

    size_t p_preamble_size();
    int p_dump_preamble(const size_t buffer_size, char *buffer);
    int p_load_preamble(const size_t buffer_size, const char *buffer);

    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, char *buffer);
    int p_load_sensitive(const size_t buffer_size, const char *buffer);

    // Static functions
    static string generate_uuid();

  private:
    map<string, Node*> *node_entries; // mapping relative_path - node
};

#endif /*__NODE_HPP__*/
