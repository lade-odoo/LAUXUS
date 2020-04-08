#include "sgx_trts.hpp"
#include "sgx_error.hpp"

#include <string>
#include <cstring>
#include <cstddef>

using namespace std;


static unsigned char count = 0;

sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes) {
  for (size_t i = 0; i < length_in_bytes; i++)
    memcpy(rand+i, &count, 1);

  count = (count + 1) % 256;
  return SGX_SUCCESS;
}
