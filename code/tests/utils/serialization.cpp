#include "../catch.hpp"
#include "../../utils/misc.hpp"
#include "../../utils/serialization.hpp"

#include <string>
#include <cstring>


using namespace std;


SCENARIO( "Files can be dumped / loaded / deleted.", "[multi-file:serialization]" ) {
  create_directory("/tmp/nexus_tests");
  string path = "/tmp/nexus_tests/empty.txt";
  GIVEN( "A non existing file" ) {
    REQUIRE( file_size(path) == 0 );

    WHEN( "content is loaded" ) {
      THEN( "the load fails" ) {
        REQUIRE( load(path, NULL) == -1);
      }
    }
  }

  AND_GIVEN( "An existing file" ) {
    WHEN( "content is dumped" ) {
      REQUIRE( dump(path, 13, "Some content.") == 13 );

      THEN( "the size is increased" ) {
        REQUIRE( file_size(path) == 13 );
      }
      AND_THEN( "the content matches when loaded" ) {
        char buffer[13];
        REQUIRE( load(path, buffer) == 13);
        REQUIRE( memcmp(buffer, "Some content.", 13) == 0);
      }
      AND_THEN( "the content matches when loaded with offset" ) {
        char buffer[8];
        REQUIRE( load_with_offset(path, 5, 10, buffer) == 8);
        REQUIRE( memcmp(buffer, "content.", 8) == 0);
      }
      AND_THEN( "the load with offset fails if the offset is too big" ) {
        char *buffer = NULL;
        REQUIRE( load_with_offset(path, 15, 5, buffer) == -1);
      }
    }
    AND_WHEN( "content is dumped with offset" ) {
      REQUIRE( dump_with_offset(path, 5, 10, "contentV2.") );

      THEN( "the size is changed" ) {
        REQUIRE( file_size(path) == 15 );
      }
      AND_THEN( "the content matches when loaded" ) {
        char buffer[15];
        REQUIRE( load(path, buffer) == 15);
        REQUIRE( memcmp(buffer, "Some contentV2.", 15) == 0);
      }
    }
    AND_WHEN( "content is appended" ) {
      REQUIRE( dump_append(path, 16, " Plus appending.") );

      THEN( "the size is changed" ) {
        REQUIRE( file_size(path) == 31 );
      }
    }
    AND_WHEN( "the file is deleted" ) {
      REQUIRE( delete_file(path) );

      THEN( "the file can no longer be loaded" ) {
        char *buffer = NULL;
        REQUIRE( load(path, buffer) == -1);
      }
    }
  }
}
