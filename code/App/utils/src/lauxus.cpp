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
  if (create_directory(CONTENT_DIR) < 0 || create_directory(META_DIR) < 0 || create_directory(AUDIT_DIR) < 0) {
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
