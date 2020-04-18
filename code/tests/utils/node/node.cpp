#include "../../catch.hpp"
#include "../../../utils/users/user.hpp"
#include "../../../utils/node/node.hpp"
#include "../../../utils/node/supernode.hpp"
#include "../../../utils/node/dirnode.hpp"
#include "../../../utils/node/filenode.hpp"
#include "../../../utils/encryption/aes_gcm.hpp"

#include <string>
#include <cstring>
#include <iostream>

using namespace std;



SCENARIO( "Node can be dumped and loaded to a buffer.", "[multi-file:node]" ) {
  AES_GCM_context *root_key = new AES_GCM_context();
  GIVEN( "A node without any sensitive informations" ) {
    string uuid = Node::generate_uuid();
    Node *node = new Node(NULL, uuid, "Test", root_key);

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      char buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it must return the same node" ) {
        Node *loaded = new Node(NULL, uuid, root_key);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    delete node; // user delete with the node
  }
  AND_GIVEN( "A node with a children" ) {
    string root_uuid = Node::generate_uuid(), child_uuid = Node::generate_uuid();
    Node *root = new Node(NULL, root_uuid, "Test", root_key);
    Node *child = new Node(NULL, child_uuid, "Children", root_key);

    REQUIRE( root->add_node_entry(child) == 0 );
    WHEN( "dumping it to a buffer" ) {
      size_t rb_size = root->e_size(), cb_size = child->e_size();
      char r_buffer[rb_size], c_buffer[cb_size];

      REQUIRE( root->e_dump(rb_size, r_buffer) == (int)rb_size );
      REQUIRE( child->e_dump(cb_size, c_buffer) == (int)cb_size );
      THEN( "loading it, it must return the same node" ) {
        Node *r_loaded = new Node(NULL, root_uuid, root_key);
        Node *c_loaded = new Node(NULL, child_uuid, root_key);

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
  AND_GIVEN( "A node with a non empty entitlements" ) {
    size_t pk_size = sizeof(sgx_ec256_public_t), sk_size = sizeof(sgx_ec256_private_t);
    sgx_ec256_public_t pk[pk_size];
    sgx_ec256_private_t sk[sk_size];

    REQUIRE( User::generate_keys(pk_size, pk, sk_size, sk) == 0 );
    User *user = new User("test", pk_size, pk);
    user->id = 1;

    string uuid = Node::generate_uuid();
    Node *node = new Node(NULL, uuid, "Test", root_key);
    REQUIRE( node->edit_user_entitlement(Node::OWNER_RIGHT, user) == 0 );

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      char buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it must return the same node" ) {
        Node *loaded = new Node(NULL, uuid, root_key);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    delete node;
    delete user;
  }
  delete root_key;
}

SCENARIO( "Node can store an access list, they can add / remove / check users.", "[multi-file:node]" ) {
  size_t pk_size = sizeof(sgx_ec256_public_t), sk_size = sizeof(sgx_ec256_private_t);
  sgx_ec256_public_t pk[pk_size];
  sgx_ec256_private_t sk[sk_size];

  REQUIRE( User::generate_keys(pk_size, pk, sk_size, sk) == 0 );
  User *user = new User("test", pk_size, pk);
  user->id = 1;

  AES_GCM_context *root_key = new AES_GCM_context();
  string uuid = Node::generate_uuid();
  Node *node = new Node(NULL, uuid, "Test", root_key);

  GIVEN( "A filenode without users" ) {
    WHEN( "a user is added" ) {
      REQUIRE( node->edit_user_entitlement(Node::WRITE_RIGHT | Node::READ_RIGHT, user) == 0 );

      THEN( "checking only its permission should return True" ) {
        REQUIRE( node->has_user_rights(Node::WRITE_RIGHT, user) );
        REQUIRE( node->has_user_rights(Node::WRITE_RIGHT | Node::READ_RIGHT, user) );
        REQUIRE( !node->has_user_rights(Node::WRITE_RIGHT | Node::EXEC_RIGHT, user) );
        REQUIRE( !node->has_user_rights(Node::OWNER_RIGHT, user) );
        REQUIRE( !node->has_user_rights(Node::EXEC_RIGHT, user) );
      }
      AND_THEN( "getting its attribute should give us the same policy" ) {
        REQUIRE( node->get_rights(user) == (Node::WRITE_RIGHT | Node::READ_RIGHT) );
      }
    }
  }
  AND_GIVEN( "A filenode with a user" ) {
    REQUIRE( node->edit_user_entitlement(Node::OWNER_RIGHT, user) == 0 );

    WHEN( "the user is removed" ) {
      REQUIRE( node->edit_user_entitlement(0, user) == 0 );

      THEN( "checking any permission will fail" ) {
        REQUIRE( !node->has_user_rights(Node::EXEC_RIGHT, user) );
        REQUIRE( !node->has_user_rights(Node::READ_RIGHT, user) );
        REQUIRE( !node->has_user_rights(Node::WRITE_RIGHT, user) );
        REQUIRE( !node->has_user_rights(Node::OWNER_RIGHT, user) );
      }
      AND_THEN( "getting its attribute should give us a policy of 0" ) {
        REQUIRE( node->get_rights(user) == 0 );
      }
    }
  }
  delete root_key;
  delete node;
  delete user;
}

SCENARIO( "Nodes can form file hierarchy.", "[multi-file:node]" ) {
  AES_GCM_context *root_key = new AES_GCM_context();
  GIVEN( "A supernode" ) {
    string uuid1 = Node::generate_uuid(), uuid2 = Node::generate_uuid(), uuid3 = Node::generate_uuid();
    Supernode *supernode = new Supernode("supernode", root_key);

    WHEN( "filenodes are added" ) {
      Filenode *filenode1 = new Filenode(supernode, uuid1, "Test1", root_key, 4096);
      Filenode *filenode2 = new Filenode(supernode, uuid2, "Test2", root_key, 4096);

      REQUIRE( supernode->add_node_entry(filenode1) == 0 );
      REQUIRE( supernode->add_node_entry(filenode2) == 0 );

      THEN( "we should retrieve a file from its path" ) {
        REQUIRE( supernode->retrieve_node("/Test1")->equals(filenode1) );
        REQUIRE( supernode->retrieve_node("/Test2")->equals(filenode2) );
        REQUIRE( supernode->retrieve_node("/")->equals(supernode) );
      }
      AND_THEN( "an incorrect path should return NULL" ) {
        REQUIRE( supernode->retrieve_node("/Wrong") == NULL );
      }
    }
    AND_WHEN( "dirnoes and filenodes are added" ) {
      Filenode *filenode1 = new Filenode(supernode, uuid1, "Test1", root_key, 4096);
      Dirnode *dirnode = new Dirnode(supernode, uuid3, "Tests", root_key);
      Filenode *filenode2 = new Filenode(dirnode, uuid2, "Test2", root_key, 4096);

      REQUIRE( supernode->add_node_entry(filenode1) == 0 );
      REQUIRE( supernode->add_node_entry(dirnode) == 0 );
      REQUIRE( dirnode->add_node_entry(filenode2) == 0 );

      THEN( "we should retrieve a file from its path" ) {
        REQUIRE( supernode->retrieve_node("/")->equals(supernode) );
        REQUIRE( supernode->retrieve_node("/Test1")->equals(filenode1) );
        REQUIRE( supernode->retrieve_node("/Tests")->equals(dirnode) );
        REQUIRE( supernode->retrieve_node("/Tests/Test2")->equals(filenode2) );
      }
      AND_THEN( "the absolute path should reflect the hierarchy" ) {
        REQUIRE( dirnode->absolute_path().compare("/Tests") == 0 );
        REQUIRE( supernode->absolute_path().compare("/") == 0 );
        REQUIRE( filenode2->absolute_path().compare("/Tests/Test2") == 0 );
      }
      AND_THEN( "an incorrect path should return NULL" ) {
        REQUIRE( supernode->retrieve_node("/Wrong") == NULL );
      }
    }
    delete supernode;
  }
  delete root_key;
}
