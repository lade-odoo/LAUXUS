#include "../catch.hpp"
#include "../../utils/headers/rights.hpp"
#include "../../Enclave/utils/headers/user.hpp"
#include "../../App/utils/headers/serialisation.hpp"
#include "../../Enclave/utils/headers/filesystem.hpp"
#include "../../Enclave/utils/headers/nodes/node.hpp"
#include "../../Enclave/utils/headers/nodes/supernode.hpp"
#include "../../Enclave/utils/headers/encryption/ecc.hpp"

#include <cerrno>
#include <string>
#include <cstring>
#include <vector>
#include <assert.h>


using namespace std;
static string CONTENT_DIR = "/tmp/lauxus_tests/contents";
static string META_DIR = "/tmp/lauxus_tests/metas";
static string AUDIT_DIR = "/tmp/lauxus_tests/audits";


FileSystem* _create_fs(User *root=NULL, User *lambda=NULL, size_t block_size=DEFAULT_BLOCK_SIZE) {
  lauxus_gcm_t *root_key = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t)); lauxus_random_gcm(root_key);
  lauxus_gcm_t *audit_root_key = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t)); lauxus_random_gcm(audit_root_key);
  Supernode *supernode = new Supernode(root_key);
  if (root != NULL)
    REQUIRE( supernode->add_user(root) == root );
  if (lambda != NULL)
    REQUIRE( supernode->add_user(lambda) == lambda );

  string dir = "/tmp/lauxus_tests";
  create_directory(dir);
  create_directory(CONTENT_DIR);
  create_directory(META_DIR);
  create_directory(AUDIT_DIR);

  assert(read_directory(CONTENT_DIR).size() == 0);
  assert(read_directory(META_DIR).size() == 0 || read_directory(META_DIR).size() == 1);
  assert(read_directory(AUDIT_DIR).size() == 0 || read_directory(AUDIT_DIR).size() == 1);

  FileSystem *fs = new FileSystem(root_key, audit_root_key, supernode, CONTENT_DIR, META_DIR, AUDIT_DIR, block_size);
  fs->current_user = root;
  fs->e_write_meta_to_disk(fs->supernode);

  return fs;
}

User* _create_user() {
  sgx_ec256_public_t *pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
  sgx_ec256_private_t *sk = (sgx_ec256_private_t*) malloc(sizeof(sgx_ec256_private_t));

  REQUIRE( lauxus_generate_ECC_keys(pk, sk) == 0 );
  User *user = new User("test", pk);
  free(pk); free(sk);
  return user;
}


TEST_CASE( "1: Newly created filesystem, everything must return -ENOENT", "[multi-file:filesystem]" ) {
  FileSystem *fs = _create_fs();
  lauxus_uuid_t *uuid = (lauxus_uuid_t*) malloc(sizeof(lauxus_uuid_t)); lauxus_random_uuid(uuid);
  lauxus_right_t rights;

  REQUIRE( fs->edit_user_entitlement("/test", lauxus_owner_right(), uuid) == -ENOENT );
  REQUIRE( fs->readdir("/").size() == 0 );
  REQUIRE( fs->get_rights("/test", &rights) == -ENOENT );
  REQUIRE( fs->entry_type("/test") == -ENOENT );
  REQUIRE( fs->file_size("/test") == -ENOENT );
  REQUIRE( fs->read_file("Testing purpose", "/test", 0, 10, NULL) == -ENOENT );
  REQUIRE( fs->write_file("Testing purpose", "/test", 0, 4, (uint8_t*)"Test") == -ENOENT );
  REQUIRE( fs->unlink("Testing purpose", "/test") == -ENOENT );

  REQUIRE( read_directory(CONTENT_DIR).size() == 0 );
  REQUIRE( read_directory(META_DIR).size() == 1 );

  free(uuid);
  delete fs;
}

TEST_CASE( "2: Filesystem can create and delete file", "[multi-file:filesystem]" ) {
  User *user = _create_user();
  FileSystem *fs = _create_fs(user);

  REQUIRE( fs->create_file("Testing purpose", "/test") == 0 );
  REQUIRE( read_directory(CONTENT_DIR).size() == 0 );
  REQUIRE( read_directory(META_DIR).size() == 2 );
  REQUIRE( read_directory(AUDIT_DIR).size() == 2 );

  REQUIRE( fs->unlink("Testing purpose", "/test") == 0 );
  REQUIRE( read_directory(CONTENT_DIR).size() == 0 );
  REQUIRE( read_directory(META_DIR).size() == 1 );
  REQUIRE( read_directory(AUDIT_DIR).size() == 1 );

  delete fs;
}

TEST_CASE( "3.a: Filesystem can write and read file", "[multi-file:filesystem]" ) {
  for (int block_size = 10; block_size < 20; block_size+=2) {
    User *user = _create_user();
    FileSystem *fs = _create_fs(user, NULL, block_size);

    REQUIRE( fs->create_file("Testing purpose", "/test") == 0 );
    REQUIRE( fs->file_size("/test") == 0 );
    REQUIRE( fs->read_file("Testing purpose", "/test", 0, 0, NULL) == 0 );
    REQUIRE( fs->read_file("Testing purpose", "/test", 0, 16, NULL) == 0 );

    REQUIRE( fs->write_file("Testing purpose", "/test", 0, 16, (uint8_t*)"This is a test !") == 16 );
    REQUIRE( fs->file_size("/test") == 16 );
    REQUIRE( fs->write_file("Testing purpose", "/test", 10, 20, (uint8_t*)"more advanced test !") == 20 );
    REQUIRE( fs->file_size("/test") == 30 );
    REQUIRE( read_directory(CONTENT_DIR).size() == 1 );
    REQUIRE( read_directory(META_DIR).size() == 2 );
    REQUIRE( read_directory(AUDIT_DIR).size() == 2 );

    uint8_t buffer[30];
    REQUIRE( fs->read_file("Testing purpose", "/test", 0, 30, buffer) == 30 );
    REQUIRE( memcmp(buffer, "This is a more advanced test !", 30) == 0 );
    REQUIRE( fs->read_file("Testing purpose", "/test", 0, 40, buffer) == 30 );
    REQUIRE( memcmp(buffer, "This is a more advanced test !", 30) == 0 );
    REQUIRE( fs->read_file("Testing purpose", "/test", 10, 20, buffer) == 20 );
    REQUIRE( memcmp(buffer, "more advanced test !", 20) == 0 );
    REQUIRE( fs->read_file("Testing purpose", "/test", 10, 40, buffer) == 20 );
    REQUIRE( memcmp(buffer, "more advanced test !", 20) == 0 );

    REQUIRE( fs->unlink("Testing purpose", "/test") == 0 );
    REQUIRE( read_directory(CONTENT_DIR).size() == 0 );
    REQUIRE( read_directory(META_DIR).size() == 1 );
    REQUIRE( read_directory(AUDIT_DIR).size() == 1 );

    delete fs;
  }
}

TEST_CASE( "3.b: Filesystem creating big file chunk by chunk", "[multi-file:filesystem]" ) {
  User *user = _create_user();
  FileSystem *fs = _create_fs(user, NULL, 54);

  string chunk = "This is a simple chunk that will be copied many times.";

  REQUIRE( fs->create_file("Testing purpose", "/test") == 0 );
  REQUIRE( fs->write_file("Testing purpose", "/test", 0, 54, (uint8_t*)chunk.data()) == 54 );
  REQUIRE( fs->write_file("Testing purpose", "/test", 54, 54, (uint8_t*)chunk.data()) == 54 );

  REQUIRE( fs->unlink("Testing purpose", "/test") == 0 );
  REQUIRE( read_directory(CONTENT_DIR).size() == 0 );
  REQUIRE( read_directory(META_DIR).size() == 1 );
  REQUIRE( read_directory(AUDIT_DIR).size() == 1 );

  delete fs;
}

TEST_CASE( "4: Filesystem can list files in a directory", "[multi-file:filesystem]" ) {
  User *user = _create_user();
  FileSystem *fs = _create_fs(user);

  REQUIRE( fs->create_file("Testing purpose", "/test1") == 0 );
  REQUIRE( fs->create_file("Testing purpose", "/test2") == 0 );
  REQUIRE( read_directory(CONTENT_DIR).size() == 0 );
  REQUIRE( read_directory(META_DIR).size() == 3 );
  REQUIRE( read_directory(AUDIT_DIR).size() == 3 );

  REQUIRE( fs->entry_type("/") == EISDIR );
  REQUIRE( fs->entry_type("/test1") == EEXIST );
  REQUIRE( fs->entry_type("/test2") == EEXIST );

  REQUIRE( fs->file_size("/test1") == 0 );
  REQUIRE( fs->file_size("/test2") == 0 );

  vector<string> ls = fs->readdir("/");
  REQUIRE( ls.size() == 2 );
  REQUIRE( find(ls.begin(), ls.end(), "test1") != ls.end() );
  REQUIRE( find(ls.begin(), ls.end(), "test2") != ls.end() );

  REQUIRE( fs->unlink("Testing purpose", "/test1") == 0 );
  REQUIRE( fs->unlink("Testing purpose", "/test2") == 0 );
  REQUIRE( read_directory(CONTENT_DIR).size() == 0 );
  REQUIRE( read_directory(META_DIR).size() == 1 );
  REQUIRE( read_directory(AUDIT_DIR).size() == 1 );

  delete fs;
}

TEST_CASE( "5: Filesystem can allow specific user entitlements", "[multi-file:filesystem]" ) {
  // User *root = _create_user();
  // User *lambda = _create_user();
  // FileSystem *fs = _create_fs(root, lambda);
  // lauxus_uuid_t *other_uuid = (lauxus_uuid_t*) malloc(sizeof(lauxus_uuid_t)); lauxus_random_uuid(other_uuid);
  //
  // REQUIRE( fs->create_file("Testing purpose", "/test1") == 0 );
  // REQUIRE( fs->create_file("Testing purpose", "/test2") == 0 );

  // // current_user = root
  // fs->current_user = root;
  // REQUIRE( fs->edit_user_entitlement("/", lauxus_read_right(), root->u_uuid) == -1 );
  // REQUIRE( fs->edit_user_entitlement("/test1", lauxus_read_right(), root->u_uuid) == -1 );
  // REQUIRE( fs->edit_user_entitlement("/test1", lauxus_read_right(), lambda->u_uuid) == 0 );
  // REQUIRE( fs->edit_user_entitlement("/test2", lauxus_write_right(), lambda->u_uuid) == 0 );
  // REQUIRE( fs->edit_user_entitlement("/test2", lauxus_write_right(), other_uuid) == -ENOENT );
  // REQUIRE( fs->get_rights("/") == (lauxus_read_right() | lauxus_write_right() | lauxus_exec_right()) );
  // REQUIRE( fs->get_rights("/test2") == (lauxus_read_right() | lauxus_write_right() | lauxus_exec_right()) );

  // // current_user = lambda
  // fs->current_user = lambda;
  // REQUIRE( fs->edit_user_entitlement("/", lauxus_read_right(), root->u_uuid) == -EACCES );
  // REQUIRE( fs->edit_user_entitlement("/test1", lauxus_read_right(), root->u_uuid) == -EACCES );
  // REQUIRE( fs->edit_user_entitlement("/test1", lauxus_read_right(), lambda->u_uuid) == -EACCES );
  // REQUIRE( fs->edit_user_entitlement("/test2", lauxus_write_right(), lambda->u_uuid) == -EACCES );
  // REQUIRE( fs->edit_user_entitlement("/test2", lauxus_write_right(), other_uuid) == -ENOENT );
  // REQUIRE( fs->get_rights("/") == (lauxus_read_right() | lauxus_exec_right()) );
  // REQUIRE( fs->get_rights("/test1") == (int)lauxus_read_right() );
  // REQUIRE( fs->get_rights("/test2") == (int)lauxus_write_right() );

  // fs->current_user = root;
  // REQUIRE( fs->unlink("Testing purpose", "/test1") == 0 );
  // REQUIRE( fs->unlink("Testing purpose", "/test2") == 0 );
  // REQUIRE( read_directory(CONTENT_DIR).size() == 0 );
  // REQUIRE( read_directory(META_DIR).size() == 1 );
  // REQUIRE( read_directory(AUDIT_DIR).size() == 1 );
  //
  // free(other_uuid);
  // delete fs;
}
