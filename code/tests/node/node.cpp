#include "../catch.hpp"
#include "../../utils/node/node.hpp"
#include "../../utils/node/supernode.hpp"
#include "../../utils/node/filenode.hpp"
#include "../../utils/encryption/aes_gcm.hpp"

#include <string>
#include <cstring>

using namespace std;



SCENARIO( "Node can be dumped and loaded to a buffer.", "[multi-file:node]" ) {
  AES_GCM_context *root_key = new AES_GCM_context();
  GIVEN( "A node without any children" ) {
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
  AND_GIVEN( "A node with a children" ) {
    string root_uuid = Node::generate_uuid(), child_uuid = Node::generate_uuid();
    Node *root = new Node(root_uuid, "Test", root_key);
    Node *child = new Node(child_uuid, "Children", root_key);

    REQUIRE( root->add_node_entry(child) == 0 );
    WHEN( "dumping it to a buffer" ) {
      size_t rb_size = root->e_size(), cb_size = child->e_size();
      char r_buffer[rb_size], c_buffer[cb_size];

      REQUIRE( root->e_dump(rb_size, r_buffer) == (int)rb_size );
      REQUIRE( child->e_dump(cb_size, c_buffer) == (int)cb_size );
      THEN( "loading it, it must return the same node" ) {
        Node *r_loaded = new Node(root_uuid, root_key);
        Node *c_loaded = new Node(child_uuid, root_key);

        REQUIRE( r_loaded->e_load(rb_size, r_buffer) == (int)rb_size );
        REQUIRE( c_loaded->e_load(cb_size, c_buffer) == (int)cb_size );

        REQUIRE( r_loaded->link_node_entry(child_uuid, c_loaded) == 0 );

        REQUIRE( r_loaded->equals(root) );
        REQUIRE( c_loaded->equals(child) );
        delete r_loaded;
      }
    }
    delete root;
  }
  delete root_key;
}

SCENARIO( "Nodes can form file hierarchy.", "[multi-file:node]" ) {
  AES_GCM_context *root_key = new AES_GCM_context();
  GIVEN( "A supernode" ) {
    string uuid1 = Node::generate_uuid(), uuid2 = Node::generate_uuid();
    Supernode *supernode = new Supernode("supernode", root_key);

    WHEN( "filenodes are added" ) {
      Filenode *filenode1 = new Filenode(uuid1, "Test1", root_key, 4096);
      Filenode *filenode2 = new Filenode(uuid2, "Test2", root_key, 4096);

      REQUIRE( supernode->add_node_entry(filenode1) == 0 );
      REQUIRE( supernode->add_node_entry(filenode2) == 0 );

      THEN( "we should retrieve a file from its path" ) {
        REQUIRE( supernode->retrieve_node("/Test1")->equals(filenode1) );
        REQUIRE( supernode->retrieve_node("/Test1")->equals(filenode1) );
      }
      AND_THEN( "an incorrect path should return NULL" ) {
        REQUIRE( supernode->retrieve_node("/Wrong") == NULL );
      }
    }
    delete supernode;
  }
  delete root_key;
}
