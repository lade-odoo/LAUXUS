#include "../App/App.hpp"
#include "../App/options_utils/options.hpp"

#include <cstring>
#include <vector>
#include <iostream>
#include <fuse.h>
#include <unistd.h>

#include "Enclave_u.h"
#include "sgx_error.h"
#include "sgx_utils/sgx_utils.h"
#include "../utils/serialization.hpp"
#include "../utils/misc.hpp"


using namespace std;

/* Global EID shared by multiple threads */
static string NEXUS_DIR;
static string RK_PATH, ARK_PATH;
static string SUPERNODE_PATH;
static string META_DIR, CONTENT_DIR, AUDIT_DIR;

static sgx_enclave_id_t ENCLAVE_ID;
static const char BUFFER_SEPARATOR = 0x1C;
static const size_t DEFAULT_BLOCK_SIZE = 4096;



void App::init(const string &binary_path) {
  NEXUS_DIR = binary_path + "/.nexus";
  RK_PATH = NEXUS_DIR + "/sealed_rk";
  ARK_PATH = NEXUS_DIR + "/sealed_ark";
  META_DIR = NEXUS_DIR + "/metadata";
  SUPERNODE_PATH = META_DIR + "/supernode";
  CONTENT_DIR = NEXUS_DIR + "/content";
  AUDIT_DIR = NEXUS_DIR + "/audit";
}


int App::init_enclave() {
  string path_token = NEXUS_DIR + "/enclave.token";
  string path_so = NEXUS_DIR + "/enclave.signed.so";
  int initialized = initialize_enclave(&ENCLAVE_ID, path_token, path_so);
  return initialized;
}

void App::destroy_enclave() {
  sgx_destroy_enclave(ENCLAVE_ID);
}


void* App::fuse_init(struct fuse_conn_info *conn) {
  if (nexus_load() < 0) {
    cout << "Failed to load the filesystem !" << endl;
    exit(1);
  }
  struct nexus_options *options = (struct nexus_options*) fuse_get_context()->private_data;
  if (nexus_login(options->user_sk_file, options->user_id) < 0) {
    cout << "Failed to login in the filesystem !" << endl;
    exit(1);
  }

  return &ENCLAVE_ID;
}

int App::nexus_create() {
  if (create_directory(CONTENT_DIR) < 0 || create_directory(META_DIR) < 0 || create_directory(AUDIT_DIR) < 0) {
    cout << "Failed to create required directories !" << endl;
    return -1;
  }
  if (init_enclave() < 0) {
    cout << "Failed to initialize the Enclave !" << endl;
    return -1;
  }

  int ret;
  sgx_status_t sgx_status = sgx_init_new_filesystem(ENCLAVE_ID, &ret, (char*)SUPERNODE_PATH.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to initialize the filesystem !", ret))
    return -1;

  sgx_status = sgx_init_dumping_folders(ENCLAVE_ID, (char*)CONTENT_DIR.c_str(), (char*)META_DIR.c_str(), (char*)AUDIT_DIR.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to initialize the filesystem !"))
    return -1;

  return 0;
}

int App::nexus_load() {
  if (init_enclave() < 0) {
    cout << "Failed to initialize the Enclave !" << endl;
    return -1;
  }

  int rk_sealed_size = file_size(RK_PATH); char sealed_rk[rk_sealed_size];
  int ark_sealed_size = file_size(ARK_PATH); char sealed_ark[ark_sealed_size];
  int e_supernode_size = file_size(SUPERNODE_PATH); char e_supernode[e_supernode_size];
  if (load(RK_PATH, sealed_rk) < 0 || load(ARK_PATH, sealed_ark) < 0 || load(SUPERNODE_PATH, e_supernode) < 0)
    return -1;

  int ret;
  sgx_status_t sgx_status = sgx_init_existing_filesystem(ENCLAVE_ID, &ret, (char*)SUPERNODE_PATH.c_str(),
                              rk_sealed_size, sealed_rk, ark_sealed_size, sealed_ark, e_supernode_size, e_supernode);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to initialize the filesystem !", ret))
    return -1;

  sgx_status = sgx_init_dumping_folders(ENCLAVE_ID, (char*)CONTENT_DIR.c_str(), (char*)META_DIR.c_str(), (char*)AUDIT_DIR.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to initialize the filesystem !"))
    return -1;

  return 0;
}

int App::nexus_login(const char *sk_path, int user_id) {
  size_t e_supernode_size = file_size(SUPERNODE_PATH);
  char e_supernode[e_supernode_size];
  if (load(SUPERNODE_PATH, e_supernode) < 0)
    return -1;

  int ret;
  sgx_status_t sgx_status = sgx_login(ENCLAVE_ID, &ret, sk_path, user_id, e_supernode_size, e_supernode);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to login to the filesystem !", ret))
    return -1;

  return 0;
}


void App::fuse_destroy(void* private_data) {
  if (nexus_destroy() < 0)
    exit(1);
}

int App::nexus_destroy() {
  int ret;
  sgx_status_t sgx_status = sgx_destroy_filesystem(ENCLAVE_ID, &ret,
            (char*)RK_PATH.c_str(), (char*)ARK_PATH.c_str(), (char*)SUPERNODE_PATH.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to destroy the filesystem !", ret))
    return -1;

  destroy_enclave();
  return 0;
}


int App::fuse_getattr(const char *path, struct stat *stbuf) {
	memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_uid = getuid();
  stbuf->st_gid = getgid();
  stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);

  int ret;
  string cleaned_path = clean_path(path);
  sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)cleaned_path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !"))
    return -EPROTO;
  if (ret == -ENOENT)
    return -ENOENT;

  int rights = 0;
  sgx_status = sgx_get_rights(ENCLAVE_ID, &rights, (char*)cleaned_path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to load file attribute !", rights))
    return -EPROTO;

  if (ret == EEXIST) {
    stbuf->st_mode = S_IFREG | (rights + rights*8 + rights*64); // 3 LSB base 8
    stbuf->st_nlink = 1;

    sgx_status = sgx_file_size(ENCLAVE_ID, &ret, (char*)cleaned_path.c_str());
    if (!is_ecall_successful(sgx_status, "[SGX] Fail to load file size !", ret))
      return -EPROTO;

    stbuf->st_size = ret;
  } else if (ret == EISDIR) {
    stbuf->st_mode = S_IFDIR | (rights + rights*8 + rights*64); // 3 LSB base 8
    stbuf->st_nlink = 2;
  }

  return 0;
}

int App::fuse_fgetattr(const char *path, struct stat *stbuf,
                   struct fuse_file_info *) {
  return fuse_getattr(path, stbuf);
}


int App::fuse_open(const char *filepath, struct fuse_file_info *) {//... must check access, do like
  string path = clean_path(filepath);
  int ret;
  sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  if (ret == EISDIR)
    return -EPROTO;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !"))
    return -EPROTO;

  return 0;
}

int App::fuse_create(const char *filepath, mode_t mode, struct fuse_file_info *) {
  string path = clean_path(filepath);
  int ret;
  sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (ret != -ENOENT)
    return -ret;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !"))
    return -EPROTO;

  sgx_status = sgx_create_file(ENCLAVE_ID, &ret, "...", (char*)path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to create file !"))
    return -EPROTO;

  if (ret < 0)
    return ret;
  return 0;
}

int App::fuse_read(const char *filepath, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *) {
  string path = clean_path(filepath);
  int ret;
  sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !") || ret != EEXIST)
    return -EPROTO;

  sgx_status = sgx_read_file(ENCLAVE_ID, &ret, "...", (char*)path.c_str(), (long)offset, size, buf);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to read file !"))
    return -EPROTO;

  return ret;
}

int App::fuse_write(const char *filepath, const char *data, size_t size, off_t offset,
                struct fuse_file_info *) {
  string path = clean_path(filepath);
  int ret;
  sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !") || ret != EEXIST)
    return -EPROTO;

  sgx_status = sgx_write_file(ENCLAVE_ID, &ret, "...", (char*)path.c_str(), (long)offset, size, data);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to write file !"))
    return -EPROTO;

  return ret;
}

int App::fuse_unlink(const char *filepath) {
  string path = clean_path(filepath);
  int ret;
  sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !") || ret != EEXIST)
    return -EPROTO;

  sgx_status = sgx_unlink(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to unlink entry !"))
    return -EPROTO;

  return 0;
}


int App::fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi) {
  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);

  int ret;
  string cleaned_path = clean_path(path);
  sgx_status_t sgx_status = sgx_ls_buffer_size(ENCLAVE_ID, &ret, (char*)cleaned_path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to load ls buffer size !"))
    return -EPROTO;

  const size_t buffer_size = ret;
  char buffer[buffer_size];
  sgx_status = sgx_readdir(ENCLAVE_ID, &ret, (char*)cleaned_path.c_str(), BUFFER_SEPARATOR, buffer_size, buffer);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to load directory entries !"))
    return -EPROTO;

  vector<string> files = tokenize(buffer_size, buffer, BUFFER_SEPARATOR);
  for (auto it = files.begin(); it != files.end(); it++) {
    filler(buf, (char*)it->c_str(), NULL, 0);
  }

  return 0;
}


int App::fuse_mkdir(const char *dirpath, mode_t) {
  string path = clean_path(dirpath);
  int ret;
  sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (ret != -ENOENT)
    return -ret;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if directory exists !"))
    return -EPROTO;

  sgx_status = sgx_mkdir(ENCLAVE_ID, &ret, "...", (char*)path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to create directory !"))
    return -EPROTO;

  if (ret < 0)
    return ret;
  return 0;
}

int App::fuse_rmdir(const char *dirpath) {
  string path = clean_path(dirpath);
  int ret;
  sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if directory exists !") || ret != EISDIR)
    return -EPROTO;

  sgx_status = sgx_rmdir(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to delete directory !"))
    return -EPROTO;

  return 0;
}

int App::fuse_opendir(const char *dirpath, struct fuse_file_info *) {
  string path = clean_path(dirpath);
  int ret;
  sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  if (ret == EEXIST)
    return -EPROTO;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !"))
    return -EPROTO;

  sgx_status = sgx_opendir(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to open directory !"))
    return -EPROTO;

  return 0;
}


int App::nexus_create_user(const char *username, const char *pk_file, const char *sk_file) {
  int ret;
  sgx_status_t sgx_status = sgx_create_user(ENCLAVE_ID, &ret, username, pk_file, sk_file);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to create a new user !", ret))
    return -1;

  return ret;
}

int App::nexus_add_user(const char *username, const char *pk_file) {
  int ret;
  size_t pk_size = file_size(pk_file); char pk[pk_size];
  if (load(pk_file, pk) < 0)
    return -1;

  sgx_status_t sgx_status = sgx_add_user(ENCLAVE_ID, &ret, username, pk_size, pk);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to add a user !"))
    return -1;

  return ret;
}

int App::nexus_remove_user(int user_id) {
  int ret;
  sgx_status_t sgx_status = sgx_remove_user(ENCLAVE_ID, &ret, user_id);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to remove a user !"))
    return -1;

  return ret;
}


int App::nexus_edit_user_entitlement(const int user_id, const char *path, const unsigned char rights) {
  int ret;
  sgx_status_t status = sgx_edit_user_entitlement(ENCLAVE_ID, &ret, path, rights, user_id);
  if (status != SGX_SUCCESS || ret < 0) {
    cout << "Impossible to edit this user policies." << endl;
    exit(1);
  }

  return 0;
}



int ocall_sign_challenge(const char *sk_path, size_t nonce_size, const char *nonce, size_t sig_size, char *sig) {
  // load sk
  size_t sk_size = file_size(sk_path); char sk[sk_size];
  if (load(sk_path, sk) < 0)
    return -1;

  // load encrypted supernode
  size_t e_supernode_size = file_size(SUPERNODE_PATH); char e_supernode[e_supernode_size];
  if (load(SUPERNODE_PATH, e_supernode) < 0)
    return -1;

  // construct the challenge
  size_t challenge_size = nonce_size + e_supernode_size;
  char challenge[challenge_size];
  memcpy(challenge, nonce, nonce_size);
  memcpy(challenge+nonce_size, e_supernode, e_supernode_size);

  // sign it
  int ret;
  sgx_status_t sgx_status = sgx_sign_message(ENCLAVE_ID, &ret, challenge_size, challenge, sk_size, sk, sig_size, sig);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to sign the challenge !", ret))
    return -1;

  return 0;
}
