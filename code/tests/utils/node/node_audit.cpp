#include "../../catch.hpp"
#include "../../../utils/node/node_audit.hpp"

#include <string>
#include <cstring>

using namespace std;



SCENARIO( "NodeAudit can be dumped and loaded to/from a buffer.", "[multi-file:node_audit]" ) {
  AES_GCM_context *root_key = new AES_GCM_context();
  GIVEN( "A single reason formatted in a string" ) {
    string reason = "This is my reason !";

    WHEN( "dumped it to a buffer" ) {
      size_t e_size = NodeAudit::e_reason_size(reason);
      char e_reason[e_size];

      REQUIRE( NodeAudit::e_reason_dump(root_key, reason, e_size, e_reason) == (int)e_size );
      THEN( "loading it must return the same reason" ) {
        string decrypted = "";

        REQUIRE( NodeAudit::e_reason_entry_load(root_key, decrypted, e_size-sizeof(int), e_reason+sizeof(int)) == (int)(e_size-sizeof(int)) );
        REQUIRE( decrypted.compare(reason) == 0 );
      }
    }
  }
  AND_GIVEN( "Multiple reasons formatted in a string" ) {
    string reason1 = "This is my first reason !";
    string reason2 = "This is my second reason !";

    WHEN( "dumped it to a buffer" ) {
      size_t e_size1 = NodeAudit::e_reason_size(reason1), e_size2 = NodeAudit::e_reason_size(reason2);
      char e_reason[e_size1+e_size2];

      REQUIRE( NodeAudit::e_reason_dump(root_key, reason1, e_size1, e_reason) == (int)e_size1 );
      REQUIRE( NodeAudit::e_reason_dump(root_key, reason2, e_size2, e_reason+e_size1) == (int)e_size2 );
      THEN( "loading it must return the same 2 reasons" ) {
        string decrypted1 = "";
        int offset1 = sizeof(int);
        REQUIRE( NodeAudit::e_reason_entry_load(root_key, decrypted1, e_size1-sizeof(int), e_reason+offset1) == (int)(e_size1-sizeof(int)) );
        REQUIRE( decrypted1.compare(reason1) == 0 );

        string decrypted2 = "";
        int offset2 = 0;
        std::memcpy(&offset2, e_reason, sizeof(int));
        offset2 += 2*sizeof(int);
        REQUIRE( offset2 == int(e_size1+sizeof(int)) );
        REQUIRE( NodeAudit::e_reason_entry_load(root_key, decrypted2, e_size2-sizeof(int), e_reason+offset2) == (int)(e_size2-sizeof(int)) );
        REQUIRE( decrypted2.compare(reason2) == 0 );
      }
    }
  }
  delete root_key;
}
