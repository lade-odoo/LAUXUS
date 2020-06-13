#include "../../catch.hpp"
#include "../../../utils/headers/rights.hpp"
#include "../../../Enclave/utils/headers/user.hpp"
#include "../../../Enclave/utils/headers/nodes/node.hpp"
#include "../../../Enclave/utils/headers/nodes/dirnode.hpp"
#include "../../../Enclave/utils/headers/nodes/filenode.hpp"
#include "../../../Enclave/utils/headers/nodes/supernode.hpp"
#include "../../../Enclave/utils/headers/encryption/aes_gcm.hpp"
#include "../../../Enclave/utils/headers/encryption/ecc.hpp"

#include <string>
#include <cstring>

using namespace std;



SCENARIO( "Node can be dumped and loaded to a buffer.", "[multi-file:node]" ) {
  lauxus_gcm_t *root_key = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t)); lauxus_random_gcm(root_key);
  GIVEN( "A node without any sensitive informations" ) {
    Node *node = new Node("Test", root_key);

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      uint8_t buffer[b_size];
      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );

      THEN( "loading it must return the same node" ) {
        Node *loaded = new Node(root_key);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    delete node; // user delete with the node
  }
  GIVEN( "A node with a children" ) {
    lauxus_uuid_t *child_uuid = (lauxus_uuid_t*) malloc(sizeof(lauxus_uuid_t)); lauxus_random_uuid(child_uuid);
    Node *root = new Node("Test", root_key);

    REQUIRE( root->add_node_entry("Child", child_uuid) == 0 );
    WHEN( "dumping it to a buffer" ) {
      size_t b_size = root->e_size();
      uint8_t buffer[b_size];

      REQUIRE( root->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it, it must return the same node" ) {
        Node *r_loaded = new Node(root_key);
        REQUIRE( r_loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( r_loaded->equals(root) );
        delete r_loaded;
      }
    }
    free(child_uuid);
    delete root;
  }
  AND_GIVEN( "A node with a non empty entitlements" ) {
    sgx_ec256_public_t *pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
    sgx_ec256_private_t *sk = (sgx_ec256_private_t*) malloc(sizeof(sgx_ec256_private_t));

    REQUIRE( lauxus_generate_ECC_keys(pk, sk) == 0 );
    User *user = new User("test", pk);
    Node *node = new Node("Test", root_key);
    REQUIRE( node->edit_user_rights(lauxus_owner_right(), user) == 0 );

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      uint8_t buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it must return the same node" ) {
        Node *loaded = new Node(root_key);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    free(pk); free(sk);
    delete node;
    delete user;
  }
  free(root_key);
}

SCENARIO( "Node can store an access list, they can add / remove / check users.", "[multi-file:node]" ) {
  sgx_ec256_public_t *pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
  sgx_ec256_private_t *sk = (sgx_ec256_private_t*) malloc(sizeof(sgx_ec256_private_t));

  REQUIRE( lauxus_generate_ECC_keys(pk, sk) == 0 );
  User *user = new User("test", pk);
  lauxus_gcm_t *root_key = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t)); lauxus_random_gcm(root_key);
  Node *node = new Node("Test", root_key);

  GIVEN( "A filenode without users" ) {
    WHEN( "a user is added" ) {
      REQUIRE( node->edit_user_rights(lauxus_create_rights(0, 1, 1, 0), user) == 0 );

      THEN( "checking only its permission should return True" ) {
        REQUIRE( node->has_user_rights(lauxus_write_right(), user) );
        REQUIRE( node->has_user_rights(lauxus_create_rights(0, 1, 1, 0), user) );
        REQUIRE( !node->has_user_rights(lauxus_create_rights(0, 1, 0, 1), user) );
        REQUIRE( !node->has_user_rights(lauxus_owner_right(), user) );
        REQUIRE( !node->has_user_rights(lauxus_create_rights(0, 0, 0, 1), user) );
      }
      AND_THEN( "getting its attribute should give us the same right" ) {
        lauxus_right_t get = node->get_rights(user), correct = lauxus_create_rights(0, 1, 1, 0);
        REQUIRE( memcmp(&get, &correct, sizeof(lauxus_right_t)) == 0);
      }
    }
  }
  AND_GIVEN( "A filenode with a user" ) {
    REQUIRE( node->edit_user_rights(lauxus_owner_right(), user) == 0 );

    WHEN( "the user is removed" ) {
      REQUIRE( node->edit_user_rights(lauxus_no_rights(), user) == 0 );

      THEN( "checking any permission will fail" ) {
        REQUIRE( !node->has_user_rights(lauxus_create_rights(0, 0, 0, 1), user) );
        REQUIRE( !node->has_user_rights(lauxus_read_right(), user) );
        REQUIRE( !node->has_user_rights(lauxus_write_right(), user) );
        REQUIRE( !node->has_user_rights(lauxus_owner_right(), user) );
      }
      AND_THEN( "getting its attribute should give us a right of 0" ) {
        // result different if run with valgrind -> why ?
        lauxus_right_t get = node->get_rights(user);
        lauxus_right_t correct = lauxus_no_rights();
        REQUIRE( memcmp(&get, &correct, sizeof(lauxus_right_t)) == 0);
      }
    }
  }

  free(pk); free(sk); free(root_key);
  delete node;
  delete user;
}
