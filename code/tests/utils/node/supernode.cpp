#include "../../catch.hpp"
#include "../../../utils/node/node.hpp"
#include "../../../utils/node/supernode.hpp"
#include "../../../utils/users/user.hpp"
#include "../../../utils/encryption/aes_gcm.hpp"

#include <string>
#include <cstring>


SCENARIO( "Supernode can be dumped and loaded to a buffer.", "[multi-file:supernode]" ) {
  AES_GCM_context *root_key = new AES_GCM_context();
  GIVEN( "A supernode with sensitive informations" ) {
    size_t pk_size = sizeof(sgx_ec256_public_t), sk_size = sizeof(sgx_ec256_private_t);
    sgx_ec256_public_t pk[pk_size];
    sgx_ec256_private_t sk[sk_size];

    REQUIRE( User::generate_keys(pk_size, pk, sk_size, sk) == 0 );
    User *user = new User("test", pk_size, pk);
    user->id = 0;

    Supernode *node = new Supernode("Test", root_key);
    REQUIRE( node->add_user(user) == user );

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      char buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it must return the same supernode" ) {
        Supernode *loaded = new Supernode("Test", root_key);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    delete node; // user delete with the node
  }
  AND_GIVEN( "A supernode with no sensitive informations" ) {
    Supernode *node = new Supernode("Test", root_key);

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      char buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it, it must return the same supernode" ) {
        Supernode *loaded = new Supernode("Test", root_key);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    delete node;
  }
  delete root_key;
}

SCENARIO( "Supernode can store users, they can be added / retrieved / removed.", "[multi-file:supernode]" ) {
  size_t pk_size = sizeof(sgx_ec256_public_t), sk_size = sizeof(sgx_ec256_private_t);
  sgx_ec256_public_t pk[pk_size];
  sgx_ec256_private_t sk[sk_size];

  REQUIRE( User::generate_keys(pk_size, pk, sk_size, sk) == 0 );
  User *user = new User("test", pk_size, pk);
  User *user2 = new User("test2", pk_size, pk);

  AES_GCM_context *root_key = new AES_GCM_context();
  Supernode *node = new Supernode("Test", root_key);

  GIVEN( "A supernode without users" ) {
    WHEN( "a user is added" ) {
      REQUIRE( node->add_user(user) == user );
      REQUIRE( node->add_user(user2) == user2 );
      THEN( "checking its id should give us back the user" ) {
        REQUIRE( node->retrieve_user(0) == user );
        REQUIRE( node->retrieve_user(1) == user2 );
      }
      AND_THEN( "checking if he is in the list should give us back the user" ) {
        REQUIRE( node->check_user(user) == user );
        REQUIRE( node->check_user(user2) == user2 );
      }
    }
  }
  AND_GIVEN( "A supernode with a user" ) {
    User *user3 = new User("test3", pk_size, pk);
    REQUIRE( node->add_user(user) == user );
    REQUIRE( node->add_user(user2) == user2 );
    REQUIRE( node->add_user(user3) == user3 );

    WHEN( "the user is removed" ) {
      REQUIRE( node->remove_user_from_id(0) == NULL );
      REQUIRE( node->remove_user_from_id(1) == user2 );
      THEN( "checking its id should not give us back the user" ) {
        REQUIRE( node->retrieve_user(0) == user );
        REQUIRE( node->retrieve_user(1) == NULL );
      }
      AND_THEN( "checking if he is in the list should not give us back the user" ) {
        REQUIRE( node->check_user(user) == user );
        REQUIRE( node->check_user(user2) == NULL );
      }
      AND_THEN( "adding a should not interfer with id assignment" ) {
        User *user4 = new User("test4", pk_size, pk);
        REQUIRE( node->add_user(user4) == user4 );
        REQUIRE( user4->id == 3 );
      }
    }
  }
  delete root_key;
  delete user2;
}
