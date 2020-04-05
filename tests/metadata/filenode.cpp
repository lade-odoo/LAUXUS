#include "../catch.hpp"
#include "../../utils/metadata/node.hpp"
#include "../../utils/metadata/filenode.hpp"
#include "../../utils/users/user.hpp"
#include "../../utils/encryption.hpp"

#include <string>
#include <cstring>

using namespace std;



SCENARIO( "Filenode can be dumped and loaded to a buffer.", "[multi-file:filenode]" ) {
  AES_GCM_context *root_key = new AES_GCM_context();
  GIVEN( "A filenode with sensitive informations" ) {
    size_t pk_size = sizeof(sgx_ec256_public_t), sk_size = sizeof(sgx_ec256_private_t);
    sgx_ec256_public_t pk[pk_size];
    sgx_ec256_private_t sk[sk_size];

    REQUIRE( User::generate_keys(pk_size, pk, sk_size, sk) == 0 );
    User *user = new User("test", pk_size, pk);
    user->id = 1;

    Filenode *node = new Filenode("Test", root_key, 4096);
    REQUIRE( node->edit_user_policy(Filenode::OWNER_POLICY, user) == 0 );
    REQUIRE( node->write(0, 21, "This is some content.") == 21 );

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      char buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it must return the same filenode" ) {
        Filenode *loaded = new Filenode("Test", root_key, 4096);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    delete node; // user delete with the node
  }
  AND_GIVEN( "A filenode with no sensitive informations" ) {
    Filenode *node = new Filenode("Test", root_key, 4096);

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      char buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it, it must return the same filenode" ) {
        Filenode *loaded = new Filenode("Test", root_key, 4096);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    delete node;
  }
  delete root_key;
}

SCENARIO( "Filenode can store an access list, they can add / remove / check users.", "[multi-file:filenode]" ) {
  size_t pk_size = sizeof(sgx_ec256_public_t), sk_size = sizeof(sgx_ec256_private_t);
  sgx_ec256_public_t pk[pk_size];
  sgx_ec256_private_t sk[sk_size];

  REQUIRE( User::generate_keys(pk_size, pk, sk_size, sk) == 0 );
  User *user = new User("test", pk_size, pk);
  user->id = 1;

  AES_GCM_context *root_key = new AES_GCM_context();
  Filenode *node = new Filenode("Test", root_key, 4096);

  GIVEN( "A filenode without users" ) {
    WHEN( "a user is added" ) {
      REQUIRE( node->edit_user_policy(Filenode::WRITE_POLICY | Filenode::READ_POLICY, user) == 0 );

      THEN( "checking only its permission should return True" ) {
        REQUIRE( node->is_user_allowed(Filenode::WRITE_POLICY, user) );
        REQUIRE( node->is_user_allowed(Filenode::WRITE_POLICY | Filenode::READ_POLICY, user) );
        REQUIRE( !node->is_user_allowed(Filenode::WRITE_POLICY | Filenode::EXEC_POLICY, user) );
        REQUIRE( !node->is_user_allowed(Filenode::OWNER_POLICY, user) );
        REQUIRE( !node->is_user_allowed(Filenode::EXEC_POLICY, user) );
      }
      AND_THEN( "getting its attribute should give us the same policy" ) {
        REQUIRE( node->getattr(user) == (Filenode::WRITE_POLICY | Filenode::READ_POLICY) );
      }
    }
  }
  AND_GIVEN( "A filenode with a user" ) {
    REQUIRE( node->edit_user_policy(Filenode::OWNER_POLICY, user) == 0 );

    WHEN( "the user is removed" ) {
      REQUIRE( node->edit_user_policy(0, user) == 0 );

      THEN( "checking any permission will fail" ) {
        REQUIRE( !node->is_user_allowed(Filenode::EXEC_POLICY, user) );
        REQUIRE( !node->is_user_allowed(Filenode::READ_POLICY, user) );
        REQUIRE( !node->is_user_allowed(Filenode::WRITE_POLICY, user) );
        REQUIRE( !node->is_user_allowed(Filenode::OWNER_POLICY, user) );
      }
      AND_THEN( "getting its attribute should give us a policy of 0" ) {
        REQUIRE( node->getattr(user) == 0 );
      }
    }
  }
  delete root_key;
  delete node; // user is deleted with the  node
}
