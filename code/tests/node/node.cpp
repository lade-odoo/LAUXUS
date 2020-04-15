#include "../catch.hpp"
#include "../../utils/node/node.hpp"
#include "../../utils/encryption/aes_gcm.hpp"

#include <string>
#include <cstring>

using namespace std;



SCENARIO( "Node can be dumped and loaded to a buffer.", "[multi-file:node]" ) {
  AES_GCM_context *root_key = new AES_GCM_context();
  GIVEN( "A node with sensitive informations" ) {
    string uuid = Node::generate_uuid();
    Node *node = new Node(uuid, "Test", root_key);

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      char buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it must return the same node" ) {
        Node *loaded = new Node(uuid, root_key);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    delete node; // user delete with the node
  }
  AND_GIVEN( "A node with no sensitive informations" ) {
    string uuid = Node::generate_uuid();
    Node *node = new Node(uuid, "Test", root_key);

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      char buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it, it must return the same node" ) {
        Node *loaded = new Node(uuid, root_key);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    delete node;
  }
  delete root_key;
}
