#ifndef _UUID_HPP_
#define _UUID_HPP_

#include "../../../flag.h"
#if EMULATING
#   include "../../../tests/SGX_Emulator/sgx_trts.hpp"
#else
#   include "sgx_trts.h"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#define UUID_SIZE    21

typedef struct _lauxus_uuid_t {
  char v[UUID_SIZE];
} lauxus_uuid_t;


void lauxus_random_uuid(lauxus_uuid_t* uuid);


#endif /*__UUID_HPP__*/
