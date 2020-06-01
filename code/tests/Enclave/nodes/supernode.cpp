#include "../../catch.hpp"
#include "../../../Enclave/utils/headers/user.hpp"
#include "../../../Enclave/utils/headers/nodes/node.hpp"
#include "../../../Enclave/utils/headers/nodes/supernode.hpp"
#include "../../../Enclave/utils/headers/encryption/aes_gcm.hpp"
#include "../../../Enclave/utils/headers/encryption/ecc.hpp"


#include <string>
#include <cstring>


SCENARIO( "Supernode can be dumped and loaded to a buffer.", "[multi-file:supernode]" ) {
  lauxus_gcm_t *root_key = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t)); lauxus_random_gcm(root_key);
  GIVEN( "A supernode with sensitive informations" ) {
    sgx_ec256_public_t *pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
    sgx_ec256_private_t *sk = (sgx_ec256_private_t*) malloc(sizeof(sgx_ec256_private_t));
    lauxus_uuid_t *child_uuid = (lauxus_uuid_t*) malloc(sizeof(lauxus_uuid_t)); lauxus_random_uuid(child_uuid);

    REQUIRE( lauxus_generate_ECC_keys(pk, sk) == 0 );
    User *user = new User("test", pk);
    user->set_root();

    Supernode *node = new Supernode(root_key);
    REQUIRE( node->add_user(user) == user );
    REQUIRE( node->add_node_entry("Test", child_uuid) == 0 );

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      uint8_t buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it must return the same supernode" ) {
        Supernode *loaded = new Supernode(root_key);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    free(sk); free(pk); free(child_uuid);
    delete node; // user delete with the node
  }
  AND_GIVEN( "A supernode with no sensitive informations" ) {
    Supernode *node = new Supernode(root_key);

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      uint8_t buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it, it must return the same supernode" ) {
        Supernode *loaded = new Supernode(root_key);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    delete node;
  }
  free(root_key);
}

SCENARIO( "Supernode can store users, they can be added / retrieved / removed.", "[multi-file:supernode]" ) {
  sgx_ec256_public_t *pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
  sgx_ec256_private_t *sk = (sgx_ec256_private_t*) malloc(sizeof(sgx_ec256_private_t));

  REQUIRE( lauxus_generate_ECC_keys(pk, sk) == 0 );
  User *user = new User("test", pk);
  User *user2 = new User("test2", pk);

  lauxus_gcm_t *root_key = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t)); lauxus_random_gcm(root_key);
  Supernode *node = new Supernode(root_key);

  GIVEN( "A supernode without users" ) {
    WHEN( "a user is added" ) {
      REQUIRE( node->add_user(user) == user );
      REQUIRE( node->add_user(user2) == user2 );
      THEN( "checking its uuid should give us back the user" ) {
        REQUIRE( node->retrieve_user(user->u_uuid) == user );
        REQUIRE( node->retrieve_user(user2->u_uuid) == user2 );
      }
      AND_THEN( "checking if he is in the list should give us back the user" ) {
        REQUIRE( node->check_user(user) == user );
        REQUIRE( node->check_user(user2) == user2 );
      }
    }
    free(pk); free(sk);
    free(root_key);
    delete node;
  }
  AND_GIVEN( "A supernode with a user" ) {
    User *user3 = new User("test3", pk);
    REQUIRE( node->add_user(user) == user );
    REQUIRE( node->add_user(user2) == user2 );
    REQUIRE( node->add_user(user3) == user3 );

    WHEN( "the user is removed" ) {
      REQUIRE( node->remove_user_from_uuid(user->u_uuid) == NULL );
      REQUIRE( node->remove_user_from_uuid(user2->u_uuid) == user2 );
      THEN( "checking its uuid should not give us back the user" ) {
        REQUIRE( node->retrieve_user(user->u_uuid) == user );
        REQUIRE( node->retrieve_user(user2->u_uuid) == NULL );
      }
      AND_THEN( "checking if he is in the list should not give us back the user" ) {
        REQUIRE( node->check_user(user) == user );
        REQUIRE( node->check_user(user2) == NULL );
      }
    }
    free(pk); free(sk);
    free(root_key);
    delete node;
    delete user2;
  }
}
