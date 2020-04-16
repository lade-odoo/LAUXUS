#include "../../catch.hpp"
#include "../../../utils/encryption/aes_ctr.hpp"

#include <string>
#include <cstring>

using namespace std;


SCENARIO( "CTR encryptions key can be dumped / loaded. They can also use to encrypt.", "[multi-file:encryption]" ) {
  AES_CTR_context *context = new AES_CTR_context();
  GIVEN( "An AES CTR context" ) {
    WHEN( "content is dumped" ) {
      size_t b_size = AES_CTR_context::size();
      char buffer[b_size];
      REQUIRE( context->dump(b_size, buffer) == (int)b_size );

      THEN( "when loading we should obtain the same object" ) {
        AES_CTR_context *loaded = new AES_CTR_context();

        REQUIRE( loaded->load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(context) );
        delete loaded;
      }
    }
    AND_WHEN( "some random content is encrypted" ) {
      size_t plain_size = 25;
      char plain[] = "This is a random content.";
      char cypher[plain_size];

      REQUIRE( context->encrypt((uint8_t*)plain, plain_size, (uint8_t*)cypher) == (int)plain_size );
      REQUIRE( memcmp(plain, cypher, plain_size) != 0 );
      THEN( "when decrypting it, we should obtain the input" ) {
        char decrypted[plain_size];

        REQUIRE( context->decrypt((uint8_t*)cypher, plain_size, (uint8_t*)decrypted) == (int)plain_size );
        REQUIRE( memcmp(plain, decrypted, plain_size) == 0 );
      }
    }
  }
  delete context;
}
