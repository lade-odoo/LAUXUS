#include "../../catch.hpp"
#include "../../../Enclave/utils/headers/nodes/filenode_content.hpp"
#include "../../../Enclave/utils/headers/encryption/aes_ctr.hpp"

#include <string>
#include <cstring>
#include <iostream>

using namespace std;


void _verify_map(map<string, size_t> infos, size_t start, size_t end, size_t offset) {
  REQUIRE( infos["start_block"] == start);
  REQUIRE( infos["end_block"] == end);
  REQUIRE( infos["offset_in_block"] == offset);
}

void _verify_read(FilenodeContent *content, long offset, size_t data_size, uint8_t *expected) {
  uint8_t buffer[data_size];
  REQUIRE( content->read(offset, data_size, buffer) == data_size );
  REQUIRE( memcmp(buffer, expected, data_size) == 0 );
}

void _verify_encrypt(FilenodeContent *content, long offset, size_t data_size, size_t expected_out, uint8_t *expected) {
  size_t buffer_size = content->e_size(offset, data_size);
  uint8_t e_buffer[buffer_size], r_buffer[data_size];
  REQUIRE( content->e_dump(offset, data_size, buffer_size, e_buffer) == expected_out );
  REQUIRE( content->e_load(offset, data_size, buffer_size, e_buffer) == buffer_size );

  REQUIRE( content->read(offset, data_size, r_buffer) == data_size );
  REQUIRE( memcmp(r_buffer, expected, data_size) == 0 );
}


TEST_CASE( "1: Computation of block_required", "[multi-file:filenode_content]" ) {
  _verify_map(FilenodeContent::block_required(10, 0, 5), 0, 0, 0);
  _verify_map(FilenodeContent::block_required(10, 0, 10), 0, 0, 0);
  _verify_map(FilenodeContent::block_required(10, 3, 5), 0, 0, 3);
  _verify_map(FilenodeContent::block_required(10, 3, 10), 0, 1, 3);
  _verify_map(FilenodeContent::block_required(10, 0, 16), 0, 1, 0);

  _verify_map(FilenodeContent::block_required(10, 0, 15), 0, 1, 0);
  _verify_map(FilenodeContent::block_required(10, 9, 15), 0, 2, 9);
  _verify_map(FilenodeContent::block_required(10, 10, 15), 1, 2, 0);
  _verify_map(FilenodeContent::block_required(10, 35, 3), 3, 3, 5);
  _verify_map(FilenodeContent::block_required(10, 35, 5), 3, 3, 5);
  _verify_map(FilenodeContent::block_required(10, 35, 6), 3, 4, 5);
}

TEST_CASE( "2: Content can be read and written", "[multi-file:filenode_content]" ) {
  map<size_t, lauxus_ctr_t*> *keys = new map<size_t, lauxus_ctr_t*>();
  FilenodeContent *content = new FilenodeContent(10, keys);

  REQUIRE( content->read(0, 0, NULL) == 0 );
  REQUIRE( content->read(10, 0, NULL) == 0 );
  REQUIRE( content->read(0, 1, NULL) == 0 );
  REQUIRE( content->write(0, 0, NULL) == 0 );
  REQUIRE( content->write(10, 0, NULL) == 0 );

  REQUIRE( content->write(0, 16, (uint8_t*)"This is a test !") == 16 );
  REQUIRE( content->size == 16 );
  REQUIRE( content->write(0, 16, (uint8_t*)"This is a test !") == 16 );
  REQUIRE( content->size == 16 );
  REQUIRE( content->write(10, 23, (uint8_t*)"more complicated test !") == 23 );
  REQUIRE( content->size == 33 );

  REQUIRE( content->read(0, 0, NULL)  == 0 );
  REQUIRE( content->read(10, 0, NULL)  == 0 );
  _verify_read(content, 0, 33, (uint8_t*)"This is a more complicated test !");
  _verify_read(content, 10, 23, (uint8_t*)"more complicated test !");
  _verify_read(content, 0, 10, (uint8_t*)"This is a ");

  for (auto it = keys->begin(); it != keys->end(); ++it)
    free(it->second);
  delete keys;
  delete content;
}

TEST_CASE( "3: Content can be dumped to buffer and loaded", "[multi-file:filenode_content]" ) {
  map<size_t, lauxus_ctr_t*> *keys = new map<size_t, lauxus_ctr_t*>();
  FilenodeContent *content = new FilenodeContent(10, keys);

  REQUIRE( content->write(0, 16, (uint8_t*)"This is a test !") == 16 );
  REQUIRE( content->e_size(0, 16) == 16 );
  REQUIRE( content->e_size(0, 11) == 16 );
  REQUIRE( content->e_size(0, 10) == 10 );
  REQUIRE( content->e_size(0, 2) == 10 );
  REQUIRE( content->e_size(5, 10) == 16 );
  REQUIRE( content->e_size(10, 1) == 6 );

  _verify_encrypt(content, 0, 16, 0, (uint8_t*)"This is a test !");
  _verify_encrypt(content, 0, 11, 0, (uint8_t*)"This is a t");
  _verify_encrypt(content, 0, 10, 0, (uint8_t*)"This is a ");
  _verify_encrypt(content, 5, 10, 0, (uint8_t*)"is a test ");
  _verify_encrypt(content, 11, 3, 10, (uint8_t*)"est");

  for (auto it = keys->begin(); it != keys->end(); ++it)
    free(it->second);
  delete keys;
  delete content;
}
