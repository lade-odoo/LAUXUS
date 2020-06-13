#include "../../catch.hpp"
#include "../../../Enclave/utils/headers/nodes/node_audit.hpp"
#include "../../../Enclave/utils/headers/encryption/aes_gcm.hpp"

#include <string>
#include <cstring>

using namespace std;



SCENARIO( "NodeAudit can be dumped and loaded to/from a buffer.", "[multi-file:node_audit]" ) {
  lauxus_gcm_t *root_key = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t)); lauxus_random_gcm(root_key);
  GIVEN( "A single reason formatted in a string" ) {
    string reason = "This is my reason !";
    NodeAudit audit(reason, root_key);

    WHEN( "dumped it to a buffer" ) {
      size_t e_size = audit.e_size();
      uint8_t e_reason[e_size];

      REQUIRE( audit.e_dump(e_size, e_reason) == (int)e_size );
      THEN( "loading it must return the same reason" ) {
        REQUIRE( audit.e_load(e_size, e_reason) == e_size );
        REQUIRE( audit.reason.compare(reason) == 0 );
      }
    }
  }
  AND_GIVEN( "Multiple reasons formatted in a string" ) {
    string reason1 = "This is my first reason !";
    string reason2 = "This is my second reason !";
    NodeAudit audit1(reason1, root_key), audit2(reason2, root_key);

    WHEN( "dumped it to a buffer" ) {
      size_t e_size1 = audit1.e_size(), e_size2 = audit2.e_size();
      uint8_t e_reason[e_size1+e_size2];

      REQUIRE( audit1.e_dump(e_size1, e_reason) == (int)e_size1 );
      REQUIRE( audit2.e_dump(e_size2, e_reason+e_size1) == (int)e_size2 );
      THEN( "loading it must return the same 2 reasons" ) {
        REQUIRE( audit1.e_load(e_size1, e_reason) == (int)(e_size1) );
        REQUIRE( audit1.reason.compare(reason1) == 0 );

        REQUIRE( audit2.e_load(e_size2, e_reason+e_size1) == (int)(e_size2) );
        REQUIRE( audit2.reason.compare(reason2) == 0 );
      }
    }
  }
  free(root_key);
}
