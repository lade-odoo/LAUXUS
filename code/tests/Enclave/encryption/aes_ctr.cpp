#include "../../catch.hpp"
#include "../../../Enclave/utils/headers/encryption/aes_ctr.hpp"

#include <string>
#include <cstring>

using namespace std;


SCENARIO( "CTR encryptions key can be dumped / loaded. They can also use to encrypt.", "[multi-file:encryption]" ) {
  lauxus_ctr_t *context = (lauxus_ctr_t*) malloc(sizeof(lauxus_ctr_t)); lauxus_random_ctr(context);
  GIVEN( "An AES CTR context" ) {
    WHEN( "content is dumped" ) {
      size_t b_size = sizeof(lauxus_ctr_t); uint8_t buffer[b_size];
      memcpy(buffer, context, sizeof(lauxus_ctr_t));

      THEN( "when loading we should obtain the same object" ) {
        lauxus_ctr_t *loaded = (lauxus_ctr_t*) malloc(sizeof(lauxus_ctr_t));

        memcpy(loaded, buffer, sizeof(lauxus_ctr_t));
        REQUIRE( memcmp(loaded, context, sizeof(lauxus_ctr_t)) == 0 );
        free(loaded);
      }
    }
    AND_WHEN( "some random content is encrypted" ) {
      size_t plain_size = 25;
      char plain[] = "This is a random content.";
      uint8_t cypher[plain_size];

      REQUIRE( lauxus_ctr_encrypt(context, (uint8_t*)plain, plain_size, cypher) == (int)plain_size );
      REQUIRE( memcmp(plain, cypher, plain_size) != 0 );
      THEN( "when decrypting it, we should obtain the input" ) {
        uint8_t decrypted[plain_size];

        REQUIRE( lauxus_ctr_decrypt(context, cypher, plain_size, decrypted) == (int)plain_size );
        REQUIRE( memcmp(plain, decrypted, plain_size) == 0 );
      }
    }
  }
  free(context);
}
