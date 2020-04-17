#include "../catch.hpp"
#include "../../utils/misc.hpp"

#include <string>
#include <vector>

using namespace std;



TEST_CASE( "1: Computation of tokenize", "[multi-file:misc]" ) {
  vector<string> result;

  result = tokenize(0, "", 0x1C);
  REQUIRE( result.size() == 0 );

  result = tokenize(6, "Token1", 0x1C);
  REQUIRE( result.size() == 0 );

  result = tokenize(7, "Token1!", '!');
  REQUIRE( result.size() == 1 );
  REQUIRE( result[0].compare("Token1") == 0 );

  result = tokenize(14, "Token1!Token2!", '!');
  REQUIRE( result.size() == 2 );
  REQUIRE( result[0].compare("Token1") == 0 );
  REQUIRE( result[1].compare("Token2") == 0 );
}

TEST_CASE( "2: Computation of get_directory", "[multi-file:misc]" ) {
  REQUIRE( get_directory(".").compare(".") == 0 );
  REQUIRE( get_directory("./").compare(".") == 0 );
  REQUIRE( get_directory("./a_file.txt").compare(".") == 0 );
  REQUIRE( get_directory("./a_dir/a_file.txt").compare("./a_dir") == 0 );
}

TEST_CASE( "3: Computation of get_filename", "[multi-file:misc]" ) {
  REQUIRE( get_filename(".").compare(".") == 0 );
  REQUIRE( get_filename("/a_file.txt").compare("a_file.txt") == 0 );
  REQUIRE( get_filename("./a_file.txt").compare("a_file.txt") == 0 );
  REQUIRE( get_filename("./a_dir/a_file.txt").compare("a_file.txt") == 0 );
}

TEST_CASE( "3: Computation of clean_path", "[multi-file:misc]" ) {
  REQUIRE( clean_path("/").compare("/") == 0 );
  REQUIRE( clean_path("/////////").compare("/") == 0 );
  REQUIRE( clean_path("/folder1/file.txt").compare("/folder1/file.txt") == 0 );
  REQUIRE( clean_path("/folder1///file.txt").compare("/folder1/file.txt") == 0 );
  REQUIRE( clean_path("/folder1/folder2///file.txt").compare("/folder1/folder2/file.txt") == 0 );
  REQUIRE( clean_path("/folder1///folder2///file.txt").compare("/folder1/folder2/file.txt") == 0 );
  REQUIRE( clean_path("/folder1/folder2///").compare("/folder1/folder2") == 0 );
  REQUIRE( clean_path("/folder1///folder2///").compare("/folder1/folder2") == 0 );
}
