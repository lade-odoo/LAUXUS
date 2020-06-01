#include "../catch.hpp"
#include "../../Enclave/utils/headers/user.hpp"
#include "../../Enclave/utils/headers/encryption/ecc.hpp"

#include <string>
#include <cstring>

using namespace std;



SCENARIO( "A user can dump his keys to a buffer then retrieve them.", "[multi-file:user]" ) {
  sgx_ec256_public_t *pk = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
  sgx_ec256_private_t *sk = (sgx_ec256_private_t*) malloc(sizeof(sgx_ec256_private_t));

  REQUIRE( lauxus_generate_ECC_keys(pk, sk) == 0 );
  User *user = new User("test", pk);
  GIVEN( "A newly created user ") {
    WHEN( "dumping to a buffer" ) {
      size_t b_size = user->size();
      uint8_t buffer[b_size];

      REQUIRE( user->dump(b_size, buffer) == (int)b_size );
      THEN( "when loaded, we retrieve the same user" ) {
        User *loaded = new User();
        REQUIRE( loaded->load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(user) );
        delete loaded;
      }
    }
  }
  free(pk); free(sk);
  delete user;
}
