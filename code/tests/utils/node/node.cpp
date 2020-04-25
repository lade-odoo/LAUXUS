#include "../../catch.hpp"
#include "../../../utils/users/user.hpp"
#include "../../../utils/node/node.hpp"
#include "../../../utils/node/supernode.hpp"
#include "../../../utils/node/dirnode.hpp"
#include "../../../utils/node/filenode.hpp"
#include "../../../utils/encryption/aes_gcm.hpp"

#include <string>
#include <cstring>

using namespace std;



SCENARIO( "Node can be dumped and loaded to a buffer.", "[multi-file:node]" ) {
  AES_GCM_context *root_key = new AES_GCM_context();
  GIVEN( "A node without any sensitive informations" ) {
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
  GIVEN( "A node with a children" ) {
    string root_uuid = Node::generate_uuid(), child_uuid = Node::generate_uuid();
    Node *root = new Node(root_uuid, "Test", root_key);

    REQUIRE( root->add_node_entry("Child", Node::generate_uuid()) == 0 );
    WHEN( "dumping it to a buffer" ) {
      size_t b_size = root->e_size();
      char buffer[b_size];

      REQUIRE( root->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it, it must return the same node" ) {
        Node *r_loaded = new Node(root_uuid, root_key);
        REQUIRE( r_loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( r_loaded->equals(root) );
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

    string uuid = Node::generate_uuid();
    Node *node = new Node(uuid, "Test", root_key);
    REQUIRE( node->edit_user_entitlement(Node::OWNER_RIGHT, user) == 0 );

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

  AES_GCM_context *root_key = new AES_GCM_context();
  string uuid = Node::generate_uuid();
  Node *node = new Node(uuid, "Test", root_key);

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
      AND_THEN( "getting its attribute should give us the same right" ) {
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
      AND_THEN( "getting its attribute should give us a right of 0" ) {
        REQUIRE( node->get_rights(user) == 0 );
      }
    }
  }
  delete root_key;
  delete node;
  delete user;
}
