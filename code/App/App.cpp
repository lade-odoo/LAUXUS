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
static string META_PATH, ENCR_PATH, AUDIT_PATH;

static sgx_enclave_id_t ENCLAVE_ID;
static const char BUFFER_SEPARATOR = 0x1C;
static const size_t DEFAULT_BLOCK_SIZE = 4096;



// okay
void App::init(const string &binary_path) {
  NEXUS_DIR = binary_path + "/.nexus";
  RK_PATH = NEXUS_DIR + "/sealed_rk";
  ARK_PATH = NEXUS_DIR + "/sealed_ark";
  SUPERNODE_PATH = NEXUS_DIR + "/supernode";
  META_PATH = NEXUS_DIR + "/metadata";
  ENCR_PATH = NEXUS_DIR + "/ciphers";
  AUDIT_PATH = NEXUS_DIR + "/audit";
}


// okay
int App::init_enclave() {
  string path_token = NEXUS_DIR + "/enclave.token";
  string path_so = NEXUS_DIR + "/enclave.signed.so";
  int initialized = initialize_enclave(&ENCLAVE_ID, path_token, path_so);
  return initialized;
}

// okay
void App::destroy_enclave() {
  sgx_destroy_enclave(ENCLAVE_ID);
}


// okay
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
  if (retrieve_nexus_content() < 0) {
    cout << "Failed to retrieve Nexus previous content !" << endl;
    exit(1);
  }

  return &ENCLAVE_ID;
}

// okay
int App::nexus_create() {
  if (create_directory(ENCR_PATH) < 0 || create_directory(META_PATH) < 0 || create_directory(AUDIT_PATH) < 0) {
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

  return 0;
}

// okay
int App::nexus_load() {
  if (init_enclave() < 0) {
    cout << "Failed to initialize the Enclave !" << endl;
    return -1;
  }

  char *sealed_rk = NULL, *sealed_ark = NULL, *e_supernode = NULL;
  int rk_sealed_size = load(RK_PATH, &sealed_rk);
  int ark_sealed_size = load(ARK_PATH, &sealed_ark);
  int e_supernode_size = load(SUPERNODE_PATH, &e_supernode);
  if (rk_sealed_size < 0 || ark_sealed_size < 0 || e_supernode_size < 0)
    return -1;

  int ret;
  sgx_status_t sgx_status = sgx_init_existing_filesystem(ENCLAVE_ID, &ret, (char*)SUPERNODE_PATH.c_str(),
                              rk_sealed_size, sealed_rk, ark_sealed_size, sealed_ark, e_supernode_size, e_supernode);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to initialize the filesystem !", ret))
    return -1;

  free(sealed_rk); free(sealed_ark); free(e_supernode);
  return 0;
}

// okay
int App::nexus_login(const char *sk_path, int user_id) {
  char *e_supernode = NULL;
  int e_supernode_size = load(SUPERNODE_PATH, &e_supernode);
  if (e_supernode_size < 0)
    return -1;

  int ret;
  sgx_status_t sgx_status = sgx_login(ENCLAVE_ID, &ret, sk_path, user_id, e_supernode_size, e_supernode);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to login to the filesystem !", ret))
    return -1;

  free(e_supernode);
  return 0;
}


// okay
void App::fuse_destroy(void* private_data) {
  if (nexus_destroy() < 0)
    exit(1);
}

// okay
int App::nexus_destroy() {
  int ret;
  sgx_status_t sgx_status = sgx_destroy_filesystem(ENCLAVE_ID, &ret,
            (char*)RK_PATH.c_str(), (char*)ARK_PATH.c_str(), (char*)SUPERNODE_PATH.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to destroy the filesystem !", ret))
    return -1;

  destroy_enclave();
  return 0;
}


int App::retrieve_nexus_content() {
  if (retrieve_nexus_meta() < 0)
    return -1;
  if (retrieve_nexus_ciphers() < 0)
    return -1;
}

// okay
int App::retrieve_nexus_meta() {
  vector<string> files = read_directory(META_PATH);
  for(auto itr = files.begin(); itr != files.end(); ++itr) {
    string uuid = *itr;
    int ret; int buffer_size; char *buffer = NULL;

    // retrieve metadata in one batch
    buffer_size = load(META_PATH + "/" + uuid, &buffer);
    if (buffer_size < 0)
      return -1;

    sgx_status_t sgx_status = sgx_e_load_metadata(ENCLAVE_ID, &ret, (char*)uuid.c_str(), buffer_size, buffer);
    if (!is_ecall_successful(sgx_status, "[SGX] Fail to load metadata !", ret))
      return -1;

    free(buffer);
  }
  return 0;
}

// okay
int App::retrieve_nexus_ciphers() {
  vector<string> files = read_directory(ENCR_PATH);

  for(auto itr = files.begin(); itr != files.end(); ++itr) {
    string filename = *itr;
    int ret; int buffer_size; char *buffer = NULL;

    for (size_t read = 0; read % DEFAULT_BLOCK_SIZE == 0; read += buffer_size) {
      buffer_size = load_with_offset(ENCR_PATH + "/" + filename, read, DEFAULT_BLOCK_SIZE, &buffer);
      if (buffer_size < 0)
        return -1;

      sgx_status_t sgx_status = sgx_e_load_file(ENCLAVE_ID, &ret, (char*)filename.c_str(), read, buffer_size, buffer);
      if (!is_ecall_successful(sgx_status, "[SGX] Fail to load file !", ret))
        return -1;

      free(buffer);
    }
  }
  return 0;
}

int App::retrieve_nexus_audits() {
  return 0;
}


// okay
int App::nexus_write_metadata(const string &filename) {
  int ret;
  sgx_status_t sgx_status = sgx_e_dump_metadata(ENCLAVE_ID, &ret, (char*)filename.c_str(), (char*)META_PATH.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to dump metadata !", ret))
    return -1;

  return ret;
}

// okay
int App::nexus_write_encryption(const string &filename, long offset, size_t updated_size) {
  int ret;
  sgx_status_t sgx_status = sgx_e_dump_file(ENCLAVE_ID, &ret, (char*)filename.c_str(), (char*)ENCR_PATH.c_str(), offset, updated_size);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to dump metadata !", ret))
    return -1;

  return ret;
}

// okay
int App::nexus_append_reason(const string &filename) {
  char *buffer = NULL;
  int reason_size = load("/tmp/nexus/" + filename + ".reason", &buffer);
  if (reason_size < 0) {
    cout << "Failed to retrieve the reason !";
    return -1;
  }

  string reason(reason_size-1, ' ');
  memcpy(const_cast<char*>(reason.data()), buffer, reason_size);
  free(buffer);

  int ret;
  sgx_status_t sgx_status = sgx_e_dump_audit(ENCLAVE_ID, &ret, (char*)filename.c_str(), (char*)AUDIT_PATH.c_str(), (char*)reason.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to dump audit !", ret))
    return -1;

  return ret;
}

// okay
int App::nexus_delete_file(const string &dir, const string &filename) {
  int ret;
  sgx_status_t sgx_status = sgx_delete_file(ENCLAVE_ID, &ret, (char*)filename.c_str(), (char*)dir.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to dump audit !", ret))
    return -1;

  return ret;
}


// okay
int App::fuse_getattr(const char *path, struct stat *stbuf) {
	memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_uid = getuid();
  stbuf->st_gid = getgid();
  stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 00777;
		stbuf->st_nlink = 2;
    return 0;
	}

  int ret;
  string filename = get_filename(path);
  sgx_status_t sgx_status = sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !"))
    return -EPROTO;

  if (ret == EEXIST) {
    sgx_status = sgx_getattr(ENCLAVE_ID, &ret, (char*)filename.c_str());
    if (!is_ecall_successful(sgx_status, "[SGX] Fail to load file attribute !", ret))
      return -EPROTO;

    stbuf->st_mode = S_IFREG | (ret + ret*8 + ret*64); // 3 LSB base 8
    stbuf->st_nlink = 1;

    sgx_status = sgx_file_size(ENCLAVE_ID, &ret, (char*)filename.c_str());
    if (!is_ecall_successful(sgx_status, "[SGX] Fail to load file size !", ret))
      return -EPROTO;

    stbuf->st_size = ret;
    return 0;
  }

  return -ENOENT;
}

// okay
int App::fuse_fgetattr(const char *path, struct stat *stbuf,
                   struct fuse_file_info *) {
  return fuse_getattr(path, stbuf);
}


// okay
int App::fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi) {
  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);

  int ret;
  sgx_status_t sgx_status = sgx_ls_buffer_size(ENCLAVE_ID, &ret);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to load ls buffer size !"))
    return -EPROTO;

  const size_t buffer_size = ret;
  char buffer[buffer_size];
  sgx_status = sgx_readdir(ENCLAVE_ID, &ret, BUFFER_SEPARATOR, buffer_size, buffer);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to load directory entries !"))
    return -EPROTO;

  vector<string> files = tokenize(buffer_size, buffer, BUFFER_SEPARATOR);
  for (auto it = files.begin(); it != files.end(); it++) {
    filler(buf, (char*)it->c_str(), NULL, 0);
  }

  return 0;
}


// okay
int App::fuse_open(const char *filepath, struct fuse_file_info *) {
  string filename = get_filename(filepath);
  int ret;
  sgx_status_t sgx_status = sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !"))
    return -EPROTO;

  return 0;
}

// okay
int App::fuse_create(const char *filepath, mode_t mode, struct fuse_file_info *) {
  string filename = get_filename(filepath);
  int ret;
  sgx_status_t sgx_status = sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == EEXIST)
    return -EEXIST;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !"))
    return -EPROTO;

  sgx_status = sgx_create_file(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to create file !"))
    return -EPROTO;

  if (ret < 0)
    return ret;
  if (nexus_append_reason(filename) < 0)
    return -EPROTO;
  if (nexus_write_metadata(filename) < 0)
    return -EPROTO;

  return 0;
}

// okay
int App::fuse_read(const char *filepath, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *) {
  string filename = get_filename(filepath);
  int ret;
  sgx_status_t sgx_status = sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !"))
    return -EPROTO;

  if (nexus_append_reason(filename) < 0)
    return -EPROTO;

  sgx_status = sgx_read_file(ENCLAVE_ID, &ret, (char*)filename.c_str(), (long)offset, size, buf);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to read file !"))
    return -EPROTO;

  if (ret < 0)
    return ret;

  return ret;
}

// okay
int App::fuse_write(const char *filepath, const char *data, size_t size, off_t offset,
                struct fuse_file_info *) {
  string filename = get_filename(filepath);
  int ret;
  sgx_status_t sgx_status = sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !"))
    return -EPROTO;

  if (nexus_append_reason(filename) < 0)
    return -EPROTO;

  sgx_status = sgx_write_file(ENCLAVE_ID, &ret, (char*)filename.c_str(), (long)offset, size, data);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to write file !"))
    return -EPROTO;

  if (ret < 0)
    return ret;
  if (nexus_write_metadata(filename) < 0)
    return -EPROTO;
  if (nexus_write_encryption(filename, (long)offset, size) < 0)
    return -EPROTO;

  return ret;
}

// okay
int App::fuse_unlink(const char *filepath) {
  string filename = get_filename(filepath);
  int ret;
  sgx_status_t sgx_status = sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check if file exists !"))
    return -EPROTO;

  if (ret < 0)
    return ret;
  if (nexus_delete_file(filename, ENCR_PATH) < 0)
    return -EPROTO;
  if (nexus_delete_file(filename, META_PATH) < 0)
    return -EPROTO;
  if (nexus_delete_file(filename, AUDIT_PATH) < 0)
    return -EPROTO;

  sgx_status = sgx_unlink(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to unlink entry !"))
    return -EPROTO;

  return 0;
}


// okay
int App::nexus_create_user(const char *username, const char *pk_file, const char *sk_file) {
  int ret;
  sgx_status_t sgx_status = sgx_create_user(ENCLAVE_ID, &ret, username, pk_file, sk_file);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to create a new user !", ret))
    return -1;

  return ret;
}

// okay
int App::nexus_add_user(const char *username, const char *pk_file) {
  int ret;
  char *pk = NULL;
  int pk_size = load(pk_file, &pk);
  if (pk_size < 0)
    return -1;
  cout << "Loaded pk" << endl;

  sgx_status_t sgx_status = sgx_add_user(ENCLAVE_ID, &ret, username, pk_size, pk);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to add a user !"))
    return -1;
  cout << "Added !" << endl;

  return ret;
}

// okay
int App::nexus_remove_user(int user_id) {
  int ret;
  sgx_status_t sgx_status = sgx_remove_user(ENCLAVE_ID, &ret, user_id);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to remove a user !"))
    return -1;

  return ret;
}

int App::nexus_edit_user_policy(const int user_id, const char *filepath, const unsigned char policy) {
  int ret;
  sgx_status_t status = sgx_edit_user_policy(ENCLAVE_ID, &ret, filepath, policy, user_id);
  if (status != SGX_SUCCESS || ret < 0) {
    cout << "Impossible to edit this user policies." << endl;
    exit(1);
  }

  App::nexus_write_metadata(filepath);
  return 0;
}


// okay
int ocall_sign_challenge(const char *sk_path, size_t nonce_size, const char *nonce, size_t sig_size, char *sig) {
  // load sk
  char *sk = NULL;
  int sk_size = load(sk_path, &sk);
  if (sk_size < 0)
    return -1;

  // load encrypted supernode
  char *e_supernode = NULL;
  int e_supernode_size = load(SUPERNODE_PATH, &e_supernode);
  if (e_supernode_size <= 0)
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
