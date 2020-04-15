#include "../catch.hpp"
#include "../../utils/node/node.hpp"
#include "../../utils/node/filenode.hpp"
#include "../../utils/users/user.hpp"
#include "../../utils/encryption/aes_gcm.hpp"

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

    string uuid = Node::generate_uuid();
    Filenode *node = new Filenode(uuid, "Test", root_key, 4096);
    REQUIRE( node->edit_user_policy(Filenode::OWNER_POLICY, user) == 0 );

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      char buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it must return the same filenode" ) {
        Filenode *loaded = new Filenode(uuid, root_key, 4096);

        REQUIRE( loaded->e_load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(node) );
        delete loaded;
      }
    }
    delete node; // user delete with the node
  }
  AND_GIVEN( "A filenode with no sensitive informations" ) {
    string uuid = Node::generate_uuid();
    Filenode *node = new Filenode(uuid, "Test", root_key, 4096);

    WHEN( "dumping it to a buffer" ) {
      size_t b_size = node->e_size();
      char buffer[b_size];

      REQUIRE( node->e_dump(b_size, buffer) == (int)b_size );
      THEN( "loading it, it must return the same filenode" ) {
        Filenode *loaded = new Filenode(uuid, root_key, 4096);

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
  string uuid = Node::generate_uuid();
  Filenode *node = new Filenode(uuid, "Test", root_key, 4096);

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

SCENARIO( "Filenode can store the content of a file.", "[multi-file:filenode]" ) {
  AES_GCM_context *root_key = new AES_GCM_context();
  GIVEN( "An empty filenode" ) {
    string uuid = Node::generate_uuid();
    Filenode *node = new Filenode(uuid, "Test", root_key, 30);

    REQUIRE( node->file_size() == 0 );
    REQUIRE( node->read(0, 10, NULL) == 0 );
    REQUIRE( node->read(10, 0, NULL) == 0 );

    WHEN( "writing into a single block" ) {
      REQUIRE( node->write(0, 18, "This is a content.") );
      REQUIRE( node->file_size() == 18 );

      REQUIRE( node->write(8, 20, "more than a content.") );
      REQUIRE( node->file_size() == 28 );
      THEN( "reading the filenode should give us the input back" ) {
        char buffer[28];
        REQUIRE( node->read(0, 28, buffer) == 28 );
        REQUIRE( memcmp(buffer, "This is more than a content.", 28) == 0 );

        char buffer2[10];
        REQUIRE( node->read(11, 10, buffer2) == 10 );
        REQUIRE( memcmp(buffer2, "e than a c", 10) == 0 );
      }
    }
    AND_WHEN( "writing more than a single block" ) {
      REQUIRE( node->write(0, 24, "This is a small content.") );
      REQUIRE( node->file_size() == 24 );

      REQUIRE( node->write(24, 26, " And I am happending more.") );
      REQUIRE( node->file_size() == 50 );
      THEN( "reading the filenode should give us the input back" ) {
        char buffer[50];
        REQUIRE( node->read(0, 50, buffer) == 50 );
        REQUIRE( memcmp(buffer, "This is a small content. And I am happending more.", 50) == 0 );

        char buffer2[10];
        REQUIRE( node->read(25, 3, buffer2) == 3 );
        REQUIRE( memcmp(buffer2, "And", 3) == 0 );
      }
    }
    delete node;
  }
  delete root_key;
}

SCENARIO( "Filenode can dump and load the encrypted content of a file", "[multi-file:filenode]" ) {
  AES_GCM_context *root_key = new AES_GCM_context();

  GIVEN( "A filenode with a single block content" ) {
    string uuid = Node::generate_uuid();
    Filenode *node = new Filenode(uuid, "Test", root_key, 30);
    REQUIRE( node->write(0, 28, "This is some random content.") );

    WHEN( "dumping it to a buffer" ) {
      REQUIRE( node->e_content_size(0, 28) == 28 );
      REQUIRE( node->e_content_size(10, 18) == 28 );

      char buffer[28], buffer2[28];
      REQUIRE( node->e_dump_content(0, 28, 28, buffer) == 0 );
      REQUIRE( node->e_dump_content(10, 8, 28, buffer2) == 0 );

      THEN( "loading it should return the input" ) {
        REQUIRE( node->e_load_content(0, 28, buffer) == 28 );
        REQUIRE( node->e_load_content(10, 28, buffer2) == 28 );

        char decrypted[28];
        REQUIRE( node->read(0, 28, decrypted) == 28 );
        REQUIRE( memcmp(decrypted, "This is some random content.", 28) == 0 );
      }
    }
    delete node;
  }
  GIVEN( "A filenode with a more than a single block content" ) {
    string uuid = Node::generate_uuid();
    Filenode *node = new Filenode(uuid, "Test", root_key, 30);
    REQUIRE( node->write(0, 52, "This is some random content. With even more content.") );

    WHEN( "dumping it to a buffer" ) {
      REQUIRE( node->e_content_size(0, 28) == 30 );
      REQUIRE( node->e_content_size(10, 18) == 30 );
      REQUIRE( node->e_content_size(10, 28) == 52 );
      REQUIRE( node->e_content_size(35, 10) == 22 );

      char buffer[30], buffer2[52], buffer3[22];
      REQUIRE( node->e_dump_content(0, 28, 30, buffer) == 0 );
      REQUIRE( node->e_dump_content(10, 28, 52, buffer2) == 0 );
      REQUIRE( node->e_dump_content(35, 10, 22, buffer3) == 30 );

      THEN( "loading it should return the input" ) {
        REQUIRE( node->e_load_content(0, 30, buffer) == 30 );
        REQUIRE( node->e_load_content(10, 52, buffer2) == 52 );
        REQUIRE( node->e_load_content(35, 22, buffer3) == 22 );

        char decrypted[52];
        REQUIRE( node->read(0, 52, decrypted) == 52 );
        REQUIRE( memcmp(decrypted, "This is some random content. With even more content.", 52) == 0 );

        char decrypted2[28];
        REQUIRE( node->read(0, 28, decrypted2) == 28 );
        REQUIRE( memcmp(decrypted2, "This is some random content.", 28) == 0 );
      }
    }
    delete node;
  }
  // multiple block
  delete root_key;
}
