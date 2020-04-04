#include "../catch.hpp"
#include "../../utils/users/user.hpp"

#include <string>
#include <cstring>

using namespace std;


SCENARIO( "A user can create his keys, sign a message and validate it.", "[multi-file:user]" ) {
  size_t pk_size = sizeof(sgx_ec256_public_t), sk_size = sizeof(sgx_ec256_private_t);
  sgx_ec256_public_t pk[pk_size];
  sgx_ec256_private_t sk[sk_size];

  REQUIRE( User::generate_keys(pk_size, pk, sk_size, sk) == 0 );
  User *user = new User("test", pk_size, pk);
  GIVEN( "A newly created user" ) {
    WHEN ( "He signs a message" ) {
      size_t sig_size = sizeof(sgx_ec256_signature_t), challenge_size = 27;
      sgx_ec256_signature_t sig[sig_size];
      char challenge[] = "This is a simple challenge.";

      REQUIRE( User::sign(challenge_size, (uint8_t*)challenge, sk_size, sk, sig_size, sig) == 0 );
      THEN( "The signature must be valid" ) {
        REQUIRE( user->validate_signature(challenge_size, (uint8_t*)challenge, sig_size, sig) == 0 );
      }
    }
  }
  delete user;
}

SCENARIO( "A user can dump his keys to a buffer then retrieve them.", "[multi-file:user]" ) {
  size_t pk_size = sizeof(sgx_ec256_public_t), sk_size = sizeof(sgx_ec256_private_t);
  sgx_ec256_public_t pk[pk_size];
  sgx_ec256_private_t sk[sk_size];

  REQUIRE( User::generate_keys(pk_size, pk, sk_size, sk) == 0 );
  User *user = new User("test", pk_size, pk);
  GIVEN( "A newly created user ") {
    WHEN( "dumping to a buffer" ) {
      size_t b_size = user->size();
      char buffer[b_size];

      REQUIRE( user->dump(b_size, buffer) == (int)b_size );
      THEN( "when loaded, we retrieve the same user" ) {
        User *loaded = new User();
        REQUIRE( loaded->load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->compare(user) == 0 );
      }
    }
  }
}
