#include "../catch.hpp"
#include "../../utils/encryption.hpp"

#include <string>
#include <cstring>

using namespace std;


SCENARIO( "CTR encryptions key can be dumped / loaded. They can also use to encrypt.", "[multi-file:encryption]" ) {
  AES_CTR_context *context = new AES_CTR_context();
  GIVEN( "An AES CTR context" ) {
    WHEN( "content is dumped" ) {
      size_t b_size = AES_CTR_context::size();
      char *buffer = new char[b_size];
      REQUIRE( context->dump(b_size, buffer) == (int)b_size );

      THEN( "when loading we should obtain the same object" ) {
        AES_CTR_context *loaded = new AES_CTR_context();

        REQUIRE( loaded->load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(context) );
        delete loaded;
      }
      delete[] buffer;
    }
    AND_WHEN( "some random content is encrypted" ) {
      size_t plain_size = 25;
      char plain[] = "This is a random content.";
      char *cypher = new char[plain_size];

      REQUIRE( context->encrypt((uint8_t*)plain, plain_size, (uint8_t*)cypher) == (int)plain_size );
      REQUIRE( memcmp(plain, cypher, plain_size) != 0 );
      THEN( "when decrypting it, we should obtain the input" ) {
        char *decrypted = new char[plain_size];

        REQUIRE( context->decrypt((uint8_t*)cypher, plain_size, (uint8_t*)decrypted) == (int)plain_size );
        REQUIRE( memcmp(plain, decrypted, plain_size) == 0 );
        delete[] decrypted;
      }
      delete[] cypher;
    }
  }
  delete context;
}

SCENARIO( "GCM encryptions key can be dumped / loaded. They can also use to encrypt.", "[multi-file:encryption]" ) {
  AES_GCM_context *context = new AES_GCM_context();
  GIVEN( "An AES GCM context" ) {
    WHEN( "content (without mac) is dumped" ) {
      size_t b_size = AES_GCM_context::size_without_mac();
      char *buffer = new char[b_size];
      REQUIRE( context->dump_without_mac(b_size, buffer) == (int)b_size );

      THEN( "when loading (without mac), we should obtain the same object" ) {
        AES_GCM_context *loaded = new AES_GCM_context();

        REQUIRE( loaded->load_without_mac(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(context) );
        delete loaded;
      }
      delete[] buffer;
    }
    AND_WHEN( "some random content is encrypted and dumped" ) {
      size_t plain_size = 25; size_t b_size = AES_GCM_context::size();
      char plain[] = "This is a random content.";
      char *cypher = new char[plain_size];
      char *buffer = new char[b_size];
      char *mac = new char[sizeof(sgx_aes_gcm_128bit_tag_t)];

      REQUIRE( context->encrypt((uint8_t*)plain, plain_size, NULL, 0, (uint8_t*)cypher) == (int)plain_size );
      REQUIRE( memcmp(plain, cypher, plain_size) != 0 );
      REQUIRE( context->dump(b_size, buffer) == (int)b_size );
      memcpy(mac, context->p_mac, sizeof(sgx_aes_gcm_128bit_tag_t));

      THEN( "when decrypting it, we should obtain the input" ) {
        char *decrypted = new char[plain_size];

        REQUIRE( context->decrypt((uint8_t*)cypher, plain_size, NULL, 0, (uint8_t*)decrypted) == (int)plain_size );
        REQUIRE( memcmp(plain, decrypted, plain_size) == 0 );
        delete[] decrypted;
      }
      AND_THEN( "when decrypting it with separate MAC, we should obtain the input" ) {
        char *decrypted = new char[plain_size];

        REQUIRE( context->decrypt_with_mac((uint8_t*)cypher, plain_size, NULL, 0,
                  (uint8_t*)decrypted, (sgx_aes_gcm_128bit_tag_t*)mac) == (int)plain_size );
        REQUIRE( memcmp(plain, decrypted, plain_size) == 0 );
        delete[] decrypted;
      }
      AND_THEN( "when loaded we should retrieve the same context" ) {
        AES_GCM_context *loaded = new AES_GCM_context();

        REQUIRE( loaded->load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(context) );
        delete loaded;
      }
      delete[] cypher;
      delete[] buffer;
      delete[] mac;
    }
    AND_WHEN( "some random content is encrypted with aad and dumped" ) {
      size_t plain_size = 25, aad_size = 21; size_t b_size = AES_GCM_context::size();
      char plain[] = "This is a random content.";
      char aad[] = "This is a random aad.";
      char *cypher = new char[plain_size];
      char *buffer = new char[b_size];
      char *mac = new char[sizeof(sgx_aes_gcm_128bit_tag_t)];

      REQUIRE( context->encrypt((uint8_t*)plain, plain_size, (uint8_t*)aad, aad_size, (uint8_t*)cypher) == (int)plain_size );
      REQUIRE( memcmp(plain, cypher, plain_size) != 0 );
      REQUIRE( context->dump(b_size, buffer) == (int)b_size );
      memcpy(mac, context->p_mac, sizeof(sgx_aes_gcm_128bit_tag_t));
      THEN( "when decrypting it, we should obtain the input" ) {
        char *decrypted = new char[plain_size];

        REQUIRE( context->decrypt((uint8_t*)cypher, plain_size, (uint8_t*)aad, aad_size, (uint8_t*)decrypted) == (int)plain_size );
        REQUIRE( memcmp(plain, decrypted, plain_size) == 0 );
        delete[] decrypted;
      }
      AND_THEN( "when decrypting it with separate MAC, we should obtain the input" ) {
        char *decrypted = new char[plain_size];

        REQUIRE( context->decrypt_with_mac((uint8_t*)cypher, plain_size, (uint8_t*)aad, aad_size,
                  (uint8_t*)decrypted, (sgx_aes_gcm_128bit_tag_t*)mac) == (int)plain_size );
        REQUIRE( memcmp(plain, decrypted, plain_size) == 0 );
        delete[] decrypted;
      }
      AND_THEN( "when loaded we should retrieve the same context" ) {
        AES_GCM_context *loaded = new AES_GCM_context();
        
        REQUIRE( loaded->load(b_size, buffer) == (int)b_size );
        REQUIRE( loaded->equals(context) );
        delete loaded;
      }
      delete[] cypher;
      delete[] buffer;
      delete[] mac;
    }
  }
  delete context;
}
