#include "../headers/user.hpp"


User::User(const string &name, const sgx_ec256_public_t *pk_u) {
  this->u_uuid = (lauxus_uuid_t*) malloc(sizeof(lauxus_uuid_t)); lauxus_random_uuid(this->u_uuid);
  this->pk_u = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
  this->name = name;

  if (pk_u != NULL)
    memcpy(this->pk_u, pk_u, sizeof(sgx_ec256_public_t));
}
User::User():User::User("", NULL) {}

User::~User() {
  free(this->u_uuid);
  free(this->pk_u);
}


bool User::is_root() {
  return memcmp(this->u_uuid, "0000-00-00-00-000000", sizeof(lauxus_uuid_t)) == 0;
}
void User::set_root() {
  memcpy(this->u_uuid, "0000-00-00-00-000000", sizeof(lauxus_uuid_t));
}
bool User::is_auditor() {
    return memcmp(this->u_uuid, "1111-11-11-11-111111", sizeof(lauxus_uuid_t)) == 0;
}
void User::set_auditor() {
  memcpy(this->u_uuid, "1111-11-11-11-111111", sizeof(lauxus_uuid_t));
}


bool User::equals(User *other) {
  return this->name.compare(other->name) == 0 &&
      memcmp(this->u_uuid->v, other->u_uuid->v, sizeof(lauxus_uuid_t)) == 0 &&
      memcmp(this->pk_u, other->pk_u, sizeof(sgx_ec256_public_t)) == 0;
}


size_t User::size() {
  return sizeof(lauxus_uuid_t) + sizeof(size_t) + this->name.length()+1 + sizeof(sgx_ec256_public_t);
}

int User::dump(const size_t buffer_size, uint8_t *buffer) {
  if (buffer_size < this->size())
    return -1;

  size_t written = 0; size_t name_len = this->name.length() + 1;
  memcpy(buffer+written, this->u_uuid, sizeof(lauxus_uuid_t)); written += sizeof(lauxus_uuid_t);
  memcpy(buffer+written, &name_len, sizeof(size_t)); written += sizeof(size_t);
  memcpy(buffer+written, this->name.c_str(), name_len); written += name_len;
  memcpy(buffer+written, this->pk_u, sizeof(sgx_ec256_public_t)); written += sizeof(sgx_ec256_public_t);

  return written;
}

int User::load(const size_t buffer_size, const uint8_t *buffer) {
  if (buffer_size < sizeof(lauxus_uuid_t)+sizeof(size_t))
    return -1;

  size_t read = 0; size_t name_len = 0;
  memcpy(this->u_uuid, buffer+read, sizeof(lauxus_uuid_t)); read+= sizeof(lauxus_uuid_t);
  memcpy(&name_len, buffer+read, sizeof(size_t)); read += sizeof(size_t);
  if (buffer_size-read < name_len+sizeof(sgx_ec256_public_t))
    return -1;

  this->name.resize(name_len-1);
  memcpy(const_cast<char*>(this->name.data()), buffer+read, name_len); read += name_len;
  memcpy(this->pk_u, buffer+read, sizeof(sgx_ec256_public_t)); read += sizeof(sgx_ec256_public_t);

  return read;
}
