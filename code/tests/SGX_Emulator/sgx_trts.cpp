#include "sgx_trts.hpp"
#include "sgx_error.hpp"

#include <string>
#include <stdlib.h>
#include <time.h>
#include <cstring>
#include <cstddef>

using namespace std;

static int count = 0;


sgx_status_t sgx_read_rand(unsigned char *rands, size_t length_in_bytes) {
  if (count == 0)
    srand(time(NULL));
  count++;

  for (size_t i = 0; i < length_in_bytes; i++) {
    unsigned char r = (unsigned char)(rand() % 256);
    memcpy(rands+i, &r, 1);
  }

  return SGX_SUCCESS;
}
