#include "node.hpp"
#include "../metadata.hpp"
#include "../encryption/aes_gcm.hpp"

#include "../../flag.h"
#if EMULATING
#  include "../../tests/SGX_Emulator/sgx_trts.hpp"
#else
#   include "sgx_trts.h"
#endif

#include <string>

using namespace std;



Node::Node(const string &path, AES_GCM_context *root_key):Metadata::Metadata(root_key) {
  this->path = path;
}

Node::~Node() {
}


string Node::generate_uuid() {
  const char possibilities[] = "0123456789abcdef";
  const bool dash[] = { 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0 };

  uint8_t indexes[16] = {0};
  sgx_read_rand(indexes, 16);

  string res;
  for (int i = 0; i < 16; i++) {
      if (dash[i]) res += "-";
      res += possibilities[indexes[i] % 16];
  }

  return res;
}
