#include "../catch.hpp"
#include "../../utils/encryption/aes_gcm.hpp"

#include <string>
#include <cstring>

using namespace std;


SCENARIO( "GCM encryptions key can be dumped / loaded. They can also use to encrypt.", "[multi-file:encryption]" ) {
  AES_GCM_context *context = new AES_GCM_context();
  GIVEN( "An AES GCM context" ) {
    WHEN( "content (without mac) is dumped" ) {
      size_t b_size = AES_GCM_context::size_without_mac();
      char buffer[b_size];
      REQUIRE( context->dump_without_mac(b_size, buffer) == (int)b_size );

      THEN( "when loading (without mac), we should obtain the same object" ) {
        AES_GCM_context *loaded = new AES_GCM_context();

        REQUIRE( loaded->load_without_mac(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(context) );
        delete loaded;
      }
    }
    AND_WHEN( "some random content is encrypted and dumped" ) {
      size_t plain_size = 25; size_t b_size = AES_GCM_context::size();
      char plain[] = "This is a random content.";
      char cypher[plain_size];
      char buffer[b_size];
      char mac[sizeof(sgx_aes_gcm_128bit_tag_t)];

      REQUIRE( context->encrypt((uint8_t*)plain, plain_size, NULL, 0, (uint8_t*)cypher) == (int)plain_size );
      REQUIRE( memcmp(plain, cypher, plain_size) != 0 );
      REQUIRE( context->dump(b_size, buffer) == (int)b_size );
      memcpy(mac, context->p_mac, sizeof(sgx_aes_gcm_128bit_tag_t));

      THEN( "when decrypting it, we should obtain the input" ) {
        char decrypted[plain_size];

        REQUIRE( context->decrypt((uint8_t*)cypher, plain_size, NULL, 0, (uint8_t*)decrypted) == (int)plain_size );
        REQUIRE( memcmp(plain, decrypted, plain_size) == 0 );
      }
      AND_THEN( "when decrypting it with separate MAC, we should obtain the input" ) {
        char decrypted[plain_size];

        REQUIRE( context->decrypt_with_mac((uint8_t*)cypher, plain_size, NULL, 0,
                  (uint8_t*)decrypted, (sgx_aes_gcm_128bit_tag_t*)mac) == (int)plain_size );
        REQUIRE( memcmp(plain, decrypted, plain_size) == 0 );
      }
      AND_THEN( "when loaded we should retrieve the same context" ) {
        AES_GCM_context *loaded = new AES_GCM_context();

        REQUIRE( loaded->load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(context) );
        delete loaded;
      }
    }
    AND_WHEN( "some random content is encrypted with aad and dumped" ) {
      size_t plain_size = 25, aad_size = 21; size_t b_size = AES_GCM_context::size();
      char plain[] = "This is a random content.";
      char aad[] = "This is a random aad.";
      char cypher[plain_size];
      char buffer[b_size];
      char mac[sizeof(sgx_aes_gcm_128bit_tag_t)];

      REQUIRE( context->encrypt((uint8_t*)plain, plain_size, (uint8_t*)aad, aad_size, (uint8_t*)cypher) == (int)plain_size );
      REQUIRE( memcmp(plain, cypher, plain_size) != 0 );
      REQUIRE( context->dump(b_size, buffer) == (int)b_size );
      memcpy(mac, context->p_mac, sizeof(sgx_aes_gcm_128bit_tag_t));
      THEN( "when decrypting it, we should obtain the input" ) {
        char decrypted[plain_size];

        REQUIRE( context->decrypt((uint8_t*)cypher, plain_size, (uint8_t*)aad, aad_size, (uint8_t*)decrypted) == (int)plain_size );
        REQUIRE( memcmp(plain, decrypted, plain_size) == 0 );
      }
      AND_THEN( "when decrypting it with separate MAC, we should obtain the input" ) {
        char decrypted[plain_size];

        REQUIRE( context->decrypt_with_mac((uint8_t*)cypher, plain_size, (uint8_t*)aad, aad_size,
                  (uint8_t*)decrypted, (sgx_aes_gcm_128bit_tag_t*)mac) == (int)plain_size );
        REQUIRE( memcmp(plain, decrypted, plain_size) == 0 );
      }
      AND_THEN( "when loaded we should retrieve the same context" ) {
        AES_GCM_context *loaded = new AES_GCM_context();

        REQUIRE( loaded->load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(context) );
        delete loaded;
      }
    }
  }
  delete context;
}
