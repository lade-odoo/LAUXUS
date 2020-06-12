#include "../headers/lauxus.hpp"


int init_enclave() {
  string path_token = NEXUS_DIR + "/enclave.token";
  string path_so = NEXUS_DIR + "/enclave.signed.so";
  int initialized = initialize_enclave(&ENCLAVE_ID, path_token, path_so);
  return initialized;
}

void destroy_enclave() {
  sgx_destroy_enclave(ENCLAVE_ID);
}


int lauxus_new() {
  if (create_directory(CONTENT_DIR) < 0 || create_directory(META_DIR) < 0 || create_directory(AUDIT_DIR) < 0 || create_directory(QUOTE_DIR) < 0) {
    cout << "Failed to create required directories !" << endl;
    return -1;
  }

  init_enclave();
  int ret;
  sgx_status_t sgx_status = sgx_new_filesystem(ENCLAVE_ID, &ret,
        (char*)CONTENT_DIR.c_str(), (char*)META_DIR.c_str(), (char*)AUDIT_DIR.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to create a new filesystem !", ret))
    return -1;

  cout << "LAUXUS filesystem successfully created !" << endl;

  lauxus_destroy();
  return 0;
}

int lauxus_load() {
  init_enclave();

  // load root keys
  size_t rk_seal_size = sizeof(lauxus_gcm_t) + sizeof(sgx_sealed_data_t);
  uint8_t sealed_rk[rk_seal_size]; uint8_t sealed_ark[rk_seal_size];

  if (load(RK_PATH, rk_seal_size, sealed_rk) < 0 ||
      load(ARK_PATH, rk_seal_size, sealed_ark) < 0)
    return -1;

  // load supernode
  size_t e_supernode_size = file_size(SUPERNODE_PATH);
  uint8_t e_supernode[e_supernode_size];
  if (load(SUPERNODE_PATH, e_supernode_size, e_supernode) < 0)
    return -1;

  int ret;
  sgx_status_t sgx_status = sgx_load_filesystem(ENCLAVE_ID, &ret,
        (sgx_sealed_data_t*)sealed_rk, rk_seal_size, (sgx_sealed_data_t*)sealed_ark, rk_seal_size,
        (uint8_t*)e_supernode, e_supernode_size,
        (char*)CONTENT_DIR.c_str(), (char*)META_DIR.c_str(), (char*)AUDIT_DIR.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to load the filesystem !", ret))
    return -1;

  return 0;
}

int lauxus_login(string sk_u_path, string str_uuid) {
  sgx_ec256_private_t sk_u;
  if (load(sk_u_path, sizeof(sgx_ec256_private_t), (uint8_t*)&sk_u) < 0)
    return -1;

  if (str_uuid.length()+1 < sizeof(lauxus_uuid_t))
    return -1;
  lauxus_uuid_t u_uuid = {0};
  memcpy(u_uuid.v, str_uuid.c_str(), sizeof(lauxus_uuid_t));

  int ret;
  sgx_status_t sgx_status = sgx_login(ENCLAVE_ID, &ret, &sk_u, &u_uuid);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to login to the filesystem !", ret))
    return -1;

  cout << "User successfully logged into LAUXUS !" << endl;
  return 0;
}

int lauxus_destroy() {
  int ret;
  sgx_status_t sgx_status = sgx_destroy_filesystem(ENCLAVE_ID, &ret, (char*)RK_PATH.c_str(), (char*)ARK_PATH.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to destroy the filesystem !", ret))
    return -1;

  destroy_enclave();
  return 0;
}


int lauxus_create_quote(string sk_u_path, string sk_eu_path, string pk_eu_path, string user_uuid) {
  init_enclave();
  int ret = -1;

  // gen sealed enclave keys (only private sealed)
  sgx_status_t sgx_status = sgx_generate_sealed_keys(ENCLAVE_ID, &ret, (char*)sk_eu_path.c_str(), (char*)pk_eu_path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to generate sealed keys !", ret))
    return -1;

  // load pk_eu
  sgx_ec256_public_t pk_eu;
  if (load(pk_eu_path, sizeof(sgx_ec256_public_t), (uint8_t*)&pk_eu) < 0)
    return -1;

  uint32_t quote_size = -1;
  sgx_quote_t* quote = sgx_generate_quote(&pk_eu, &quote_size);
  if (quote == NULL)
    return -1;

  // transform quote into base64
  size_t b64_quote_size = Base64encode_len(quote_size);
  uint8_t b64_quote[b64_quote_size];
  if (Base64encode((char*)b64_quote, (char*)quote, quote_size) < 0)
    return -1;

  // sign quote
  sgx_ec256_private_t sk_u;
  if (load(sk_u_path, sizeof(sgx_ec256_private_t), (uint8_t*)&sk_u) < 0)
    return -1;

  sgx_ec256_signature_t signature;
  sgx_status = sgx_sign_message(ENCLAVE_ID, &ret, b64_quote_size, b64_quote, &sk_u, &signature);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to sign the quote !", ret))
    return -1;

  // construct dumppath
  string dumpdir(QUOTE_DIR); dumpdir.append("/"); dumpdir.append(user_uuid);
  string dumppath(dumpdir); dumppath.append("/quote");

  // create directory
  if (create_directory(dumpdir) < 0)
    return -1;

  // dump to buffer
  uint8_t dump_buffer[sizeof(sgx_ec256_signature_t)+b64_quote_size];
  memcpy(dump_buffer, &signature, sizeof(sgx_ec256_signature_t));
  memcpy(dump_buffer+sizeof(sgx_ec256_signature_t), b64_quote, b64_quote_size);
  if (dump(dumppath, sizeof(sgx_ec256_signature_t)+b64_quote_size, dump_buffer) < 0)
    return -1;

  free(quote);
  cout << "User quote successfully created !" << endl;
  return 0;
}

sgx_ec256_public_t *lauxus_verify_quote(string pk_o_path, string other_user_uuid) {
  string quotepath(QUOTE_DIR); quotepath.append("/"); quotepath.append(other_user_uuid); quotepath.append("/quote");
  int quote_size = file_size(quotepath);
  if (quote_size < 0)
    return NULL;

  uint8_t buffer[quote_size];
  if (load(quotepath, quote_size, buffer) < 0)
    return NULL;

  sgx_ec256_public_t pk_u;
  if (load(pk_o_path, sizeof(sgx_ec256_public_t), (uint8_t*)&pk_u) < 0)
    return NULL;

  sgx_ec256_signature_t signature;
  size_t b64_quote_size = quote_size-sizeof(sgx_ec256_signature_t);
  uint8_t b64_quote[b64_quote_size];
  memcpy(&signature, buffer, sizeof(sgx_ec256_signature_t));
  memcpy(b64_quote, buffer+sizeof(sgx_ec256_signature_t), b64_quote_size);

  // check signature
  int ret = -1;
  sgx_status_t sgx_status = sgx_validate_signature(ENCLAVE_ID, &ret, b64_quote_size, b64_quote, &pk_u, &signature);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to validate the quote signature !", ret))
    return NULL;

  // verify quote
  sgx_ec256_public_t *pk_eo = sgx_verify_quote(b64_quote_size, b64_quote); // pk of the enclave of the other user
  if (pk_eo == NULL)
    return NULL;
  return pk_eo;
}

int lauxus_get_shared_rk(string sk_u_path, string pk_o_path, string other_user_uuid) {
  init_enclave(); // load check admin ?
  sgx_ec256_public_t *pk_eo = lauxus_verify_quote(pk_o_path, other_user_uuid);
  if (pk_eo == NULL)
    return -1;

  // load sealed root key
  size_t rk_seal_size = sizeof(lauxus_gcm_t) + sizeof(sgx_sealed_data_t);
  uint8_t sealed_rk[rk_seal_size];
  if (load(RK_PATH, rk_seal_size, sealed_rk) < 0) {
    free(pk_eo);
    return -1;
  }

  int ret = -1;
  uint8_t e_rk[sizeof(lauxus_gcm_t)];
  sgx_ec256_public_t pk_eph;
  sgx_status_t sgx_status = sgx_get_shared_rk(ENCLAVE_ID, &ret, sizeof(lauxus_gcm_t), e_rk, &pk_eph, rk_seal_size, (sgx_sealed_data_t*)sealed_rk, pk_eo);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to generate shared root key !", ret)) {
    free(pk_eo);
    return -1;
  }

  // sign encrypted root key
  sgx_ec256_private_t sk_u;
  if (load(sk_u_path, sizeof(sgx_ec256_private_t), (uint8_t*)&sk_u) < 0) {
    free(pk_eo);
    return -1;
  }

  sgx_ec256_signature_t signature;
  sgx_status = sgx_sign_message(ENCLAVE_ID, &ret, sizeof(lauxus_gcm_t), e_rk, &sk_u, &signature);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to sign the encrypted root key !", ret)) {
    free(pk_eo);
    return -1;
  }

  // construct dumppath
  string dumpdir(QUOTE_DIR); dumpdir.append("/"); dumpdir.append(other_user_uuid);
  string dumppath(dumpdir); dumppath.append("/shared_rk");

  // dump to buffer
  int written = 0;
  uint8_t dump_buffer[sizeof(sgx_ec256_public_t)+sizeof(sgx_ec256_signature_t)+sizeof(lauxus_gcm_t)];
  memcpy(dump_buffer+written, &pk_eph, sizeof(sgx_ec256_public_t)); written += sizeof(sgx_ec256_public_t);
  memcpy(dump_buffer+written, &signature, sizeof(sgx_ec256_signature_t)); written += sizeof(sgx_ec256_signature_t);
  memcpy(dump_buffer+written, e_rk, sizeof(lauxus_gcm_t)); written += sizeof(lauxus_gcm_t);
  if (dump(dumppath, written, dump_buffer) < 0) {
    free(pk_eo);
    return -1;
  }

  free(pk_eo);
  cout << "Shared root key successfully created for user: " << other_user_uuid << " !" << endl;
  return 0;
}

int lauxus_retrieve_shared_rk(string sk_eu_path, string user_uuid, string pk_o_path, string other_user_uuid) {
  init_enclave(); // check other is admin ?
  sgx_ec256_public_t *pk_eo = lauxus_verify_quote(pk_o_path, other_user_uuid);
  if (pk_eo == NULL)
    return -1;
  free(pk_eo);

  // load pk_eph, signature, e_rk
  string shared_rk_path(QUOTE_DIR); shared_rk_path.append("/"); shared_rk_path.append(user_uuid); shared_rk_path.append("/shared_rk");
  int shared_rk_size = file_size(shared_rk_path);
  if (shared_rk_size < 0)
    return -1;

  uint8_t buffer[shared_rk_size];
  if (load(shared_rk_path, shared_rk_size, buffer) < 0)
    return -1;

  int read = 0;
  sgx_ec256_public_t pk_eph;
  sgx_ec256_signature_t e_rk_signature;
  size_t e_rk_size = shared_rk_size - sizeof(sgx_ec256_public_t) - sizeof(sgx_ec256_signature_t);
  uint8_t e_rk[e_rk_size];
  memcpy(&pk_eph, buffer+read, sizeof(sgx_ec256_public_t)); read += sizeof(sgx_ec256_public_t);
  memcpy(&e_rk_signature, buffer+read, sizeof(sgx_ec256_signature_t)); read += sizeof(sgx_ec256_signature_t);
  memcpy(e_rk, buffer+read, e_rk_size); read += e_rk_size;

  // verify signature of shared rk
  sgx_ec256_public_t pk_o;
  if (load(pk_o_path, sizeof(sgx_ec256_public_t), (uint8_t*)&pk_o) < 0)
    return -1;

  int ret = -1;
  sgx_status_t sgx_status = sgx_validate_signature(ENCLAVE_ID, &ret, e_rk_size, e_rk, &pk_o, &e_rk_signature);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to validate signature of shared rk !", ret))
    return -1;

  // load secret key of enclave of user to recompute shared secret (which is sealed)
  size_t sealed_sk_eu_size = sizeof(sgx_ec256_private_t) + sizeof(sgx_sealed_data_t);
  uint8_t sealed_sk_eu[sealed_sk_eu_size];
  if (load(sk_eu_path, sealed_sk_eu_size, sealed_sk_eu) < 0)
    return -1;

  // retrieve shared key (wich dump the sealed root key)
  sgx_status = sgx_retrieve_shared_rk(ENCLAVE_ID, &ret, (char*)RK_PATH.c_str(), e_rk_size, e_rk, &pk_eph, sealed_sk_eu_size, (sgx_sealed_data_t*)sealed_sk_eu);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to retrieve shared root key !", ret))
    return -1;

  cout << "Shared root key successfully retrieved and sealed from user: " << other_user_uuid << " !" << endl;
  return 0;
}


int lauxus_new_keys(string sk_u_path, string pk_u_path) {
  init_enclave();
  sgx_ec256_public_t pk_u; sgx_ec256_private_t sk_u;
  int ret;
  sgx_status_t sgx_status = sgx_new_user_keys(ENCLAVE_ID, &ret, &pk_u, &sk_u);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to generate new user keys !", ret))
    return -1;

  if (dump(sk_u_path, sizeof(sgx_ec256_private_t), (uint8_t*)&sk_u) < 0 ||
      dump(pk_u_path, sizeof(sgx_ec256_public_t), (uint8_t*)&pk_u) < 0)
    return -1;

  cout << "LAUXUS user keys successfully generated !" << endl;
  destroy_enclave();
  return 0;
}


int lauxus_add_user(string username, string pk_u_path) {
  lauxus_load();
  sgx_ec256_public_t pk_u;
  if (load(pk_u_path, sizeof(sgx_ec256_public_t), (uint8_t*)&pk_u) < 0)
    return -1;


  int ret;
  lauxus_uuid_t u_uuid = {0};
  sgx_status_t sgx_status = sgx_add_user(ENCLAVE_ID, &ret, (char*)username.c_str(), &pk_u, &u_uuid);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to add new users !", ret))
    return -1;

  lauxus_destroy();
  string str_uuid(" ", sizeof(lauxus_uuid_t));
  memcpy(const_cast<char*>(str_uuid.data()), u_uuid.v, sizeof(lauxus_uuid_t));
  cout << "User successfully added to LAUXUS filesystem with the following UUID: " << str_uuid << endl;
  return 0;
}

int lauxus_remove_user(string str_uuid) {
  if (str_uuid.length() < sizeof(lauxus_uuid_t))
    return -1;
  lauxus_uuid_t u_uuid = {0};
  memcpy(u_uuid.v, str_uuid.c_str(), sizeof(lauxus_uuid_t));

  int ret;
  sgx_status_t sgx_status = sgx_remove_user(ENCLAVE_ID, &ret, &u_uuid);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to remove users !", ret))
    return -1;

  lauxus_destroy();
  cout << "User successfully removed from LAUXUS filesystem !" << endl;
  return 0;
}

int lauxus_edit_user_entitlement(string path, string str_uuid,
              int owner_right, int read_right, int write_right, int exec_right) {
  lauxus_load();
  cout << "Updating user entitlement ..." << endl;

  if (str_uuid.length() < sizeof(lauxus_uuid_t))
    return -1;
  lauxus_uuid_t u_uuid = {0};
  memcpy(u_uuid.v, str_uuid.c_str(), sizeof(lauxus_uuid_t));

  lauxus_right_t right;
  right.owner = (owner_right > 0) ? 1 : 0;
  right.read = (read_right > 0) ? 1 : 0;
  right.write = (write_right > 0) ? 1 : 0;
  right.exec = (exec_right > 0) ? 1 : 0;

  int ret;
  sgx_status_t sgx_status = sgx_edit_user_entitlement(ENCLAVE_ID, &ret, (char*)path.c_str(), right, &u_uuid);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to edit user entitlement !", ret))
    return -1;

  lauxus_destroy();
  cout << "User entitlement successfully updated !" << endl;
  return 0;
}
