#include "../catch.hpp"
#include "../../utils/misc.hpp"

#include <string>
#include <vector>
#include <iostream>

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

TEST_CASE( "2: Computation of get_directory_path", "[multi-file:misc]" ) {
  REQUIRE( get_directory_path("/").compare("/") == 0 );
  REQUIRE( get_directory_path("/a_file.txt").compare("/") == 0 );
  REQUIRE( get_directory_path("/a_dir/a_file.txt").compare("/a_dir") == 0 );
}

TEST_CASE( "3: Computation of get_relative_path", "[multi-file:misc]" ) {
  REQUIRE( get_relative_path("/file.txt").compare("file.txt") == 0 );
  REQUIRE( get_relative_path("/dir/file.txt").compare("file.txt") == 0 );
  REQUIRE( get_relative_path("/dir/").compare("dir") == 0 );
  REQUIRE( get_relative_path("/dir").compare("dir") == 0 );
}

TEST_CASE( "4: Computation of get_parent_path", "[multi-file:misc]" ) {
  REQUIRE( get_parent_path("/").compare("/") == 0 );
  REQUIRE( get_parent_path("a_dir/a_file.txt").compare("a_dir") == 0 );
  REQUIRE( get_parent_path("/dir/file.txt").compare("/") == 0 );
}

TEST_CASE( "5: Computation of get_child_path", "[multi-file:misc]" ) {
  REQUIRE( get_child_path("/").compare("") == 0 );
  REQUIRE( get_child_path("/file.txt").compare("file.txt") == 0 );
  REQUIRE( get_child_path("/dir/file.txt").compare("dir/file.txt") == 0 );
}

TEST_CASE( "6: Computation of clean_path", "[multi-file:misc]" ) {
  REQUIRE( clean_path("/").compare("/") == 0 );
  REQUIRE( clean_path("/////////").compare("/") == 0 );
  REQUIRE( clean_path("/folder1/file.txt").compare("/folder1/file.txt") == 0 );
  REQUIRE( clean_path("/folder1///file.txt").compare("/folder1/file.txt") == 0 );
  REQUIRE( clean_path("/folder1/folder2///file.txt").compare("/folder1/folder2/file.txt") == 0 );
  REQUIRE( clean_path("/folder1///folder2///file.txt").compare("/folder1/folder2/file.txt") == 0 );
  REQUIRE( clean_path("/folder1/folder2///").compare("/folder1/folder2") == 0 );
  REQUIRE( clean_path("/folder1///folder2///").compare("/folder1/folder2") == 0 );
}
