#include "sgx_trts.hpp"
#include "sgx_error.hpp"

#include <string>
#include <cstring>
#include <cstddef>

using namespace std;



sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes) {
  unsigned char c = 0x44;
  for (size_t i = 0; i < length_in_bytes; i++)
    memcpy(rand+i, &c, 1);

  return SGX_SUCCESS;
}
