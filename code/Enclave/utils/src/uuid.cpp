#include "../headers/uuid.hpp"


void lauxus_random_uuid(lauxus_uuid_t* uuid) {
  const char possibilities[] = "0123456789abcdef";
  const bool dash[] = { 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 };

  uint8_t indexes[UUID_SIZE] = {0};
  sgx_read_rand(indexes, UUID_SIZE);

  for (int i = 0; i < UUID_SIZE; i++) {
    if (dash[i]) uuid->v[i] = '-';
    else uuid->v[i] = possibilities[indexes[i] % 16];
  }
  uuid->v[UUID_SIZE-1] = '\0';
}
