#include "../catch.hpp"
#include "../../utils/metadata/node.hpp"
#include "../../utils/metadata/supernode.hpp"
#include "../../utils/users/user.hpp"
#include "../../utils/encryption.hpp"

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

        REQUIRE( loaded->e_load(NULL, b_size, buffer) == (int)b_size );
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

        REQUIRE( loaded->e_load(NULL, b_size, buffer) == (int)b_size );
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
  user->id = 0;

  AES_GCM_context *root_key = new AES_GCM_context();
  Supernode *node = new Supernode("Test", root_key);

  GIVEN( "A supernode without users" ) {
    WHEN( "a user is added" ) {
      REQUIRE( node->add_user(user) == user );
      THEN( "checking its id should give us back the user" ) {
        REQUIRE( node->retrieve_user(0) == user );
      }
      AND_THEN( "checking if he is in the list should give us back the user" ) {
        REQUIRE( node->check_user(user) == user );
      }
    }
  }
  AND_GIVEN( "A supernode with a user" ) {
    REQUIRE( node->add_user(user) == user );

    WHEN( "the user is removed" ) {
      REQUIRE( node->remove_user(user) == user );
      THEN( "checking its id should not give us back the user" ) {
        REQUIRE( node->retrieve_user(0) == NULL );
      }
      AND_THEN( "checking if he is in the list should not give us back the user" ) {
        REQUIRE( node->check_user(user) == NULL );
      }
    }
  }
  delete root_key;
  delete node; // user is deleted with the  node
}
