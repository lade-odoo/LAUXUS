#define FUSE_USE_VERSION 29

#include <stdio.h>
#include <cstring>
#include <vector>
#include <iostream>
#include <fuse.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "sgx_utils/sgx_utils.h"
#include "../utils/serialization.hpp"
#include "../utils/misc.hpp"

/* Global EID shared by multiple threads */
static sgx_enclave_id_t ENCLAVE_ID;
static const char BUFFER_SEPARATOR = 0x1C;
static std::string NEXUS_DIR, META_PATH, ENCR_PATH, RK_PATH, SUPERNODE_PATH;
static const size_t DEFAULT_BLOCK_SIZE = 4096;


static struct options {
  int new_user, create_fs, show_help;
	char *user_pk_file, *user_sk_file, *username;
	char *new_user_pk_file, *new_username;
} options;

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("-h", show_help),
	OPTION("--help", show_help),

	OPTION("--create_fs", create_fs),
	OPTION("--user_pk_file=%s", user_pk_file),
	OPTION("--user_sk_file=%s", user_sk_file),
	OPTION("--username=%s", username),

	OPTION("--new_user", new_user),
  OPTION("--new_user_pk_file=%s", new_user_pk_file),
	OPTION("--new_username=%s", new_username),
	FUSE_OPT_END
};



// OCall implementations
void ocall_print(const char* str) {
  printf("%s\n", str);
}



static int nexus_write_metadata(const std::string &filename) {
  int ret;
  sgx_metadata_size(ENCLAVE_ID, &ret, (char*)filename.c_str());
  const size_t buffer_size = ret; char *buffer = (char*) malloc(buffer_size);

  sgx_dump_metadata(ENCLAVE_ID, &ret, (char*)filename.c_str(), buffer_size, buffer);
  dump(META_PATH + "/" + filename, buffer_size, buffer);

  free(buffer);
  return ret;
}

static int nexus_write_encryption(const std::string &filename, long offset, size_t updated_size) {
  int ret;
  sgx_encryption_size(ENCLAVE_ID, &ret, (char*)filename.c_str(), offset, updated_size);
  const size_t buffer_size = ret; char *buffer = (char*) malloc(buffer_size);

  sgx_dump_encryption(ENCLAVE_ID, &ret, (char*)filename.c_str(), offset, updated_size, buffer_size, buffer);
  dump_with_offset(ENCR_PATH + "/" + filename, ret, buffer_size, buffer); // dump with return offset

  free(buffer);
  return ret;
}


static void retrieve_nexus_meta() {
  std::vector<std::string> files = read_directory(META_PATH);
  for(auto itr = files.begin(); itr != files.end(); ++itr) {
    std::string filename = *itr; int ret; size_t buffer_size; char *buffer = NULL;

    // retrieve metadata in one batch
    buffer_size = load(META_PATH + "/" + filename, &buffer);
    sgx_load_metadata(ENCLAVE_ID, &ret, (char*)filename.c_str(), buffer_size, buffer);
    free(buffer);
  }
}

static void retrieve_nexus_ciphers() {
  std::vector<std::string> files = read_directory(ENCR_PATH);

  for(auto itr = files.begin(); itr != files.end(); ++itr) {
    std::string filename = *itr; int ret; size_t buffer_size; char *buffer = NULL;

    for (size_t read = 0; read % DEFAULT_BLOCK_SIZE == 0; read += buffer_size) {
      buffer_size = load_with_offset(ENCR_PATH + "/" + filename, read, DEFAULT_BLOCK_SIZE, &buffer);
      sgx_load_encryption(ENCLAVE_ID, &ret, (char*)filename.c_str(), read, buffer_size, buffer);
      free(buffer);
    }
  }
}

static void retrieve_nexus() {
  retrieve_nexus_meta();
  retrieve_nexus_ciphers();
}


static void* nexus_init_existing() {
  int ret;
  int rk_sealed_size; char *sealed_rk = NULL;
  int supernode_size; char *supernode = NULL;
  int pk_size; char *pk = NULL;
  int sk_size; char *sk = NULL;
  size_t nonce_size = 32; char nonce[nonce_size];
  size_t sig_size = sizeof(sgx_ec256_signature_t); char sig[sig_size];

  rk_sealed_size = load(RK_PATH, &sealed_rk);
  supernode_size = load(SUPERNODE_PATH, &supernode);
  pk_size = load(options.user_pk_file, &pk);
  sk_size = load(options.user_sk_file, &sk);
  if (rk_sealed_size < 0 || supernode_size < 0 || pk_size < 0 || sk_size < 0)
    exit(1);

  sgx_status_t status = sgx_init_existing_filesystem(ENCLAVE_ID, &ret, (char*)SUPERNODE_PATH.c_str(),
                                                    rk_sealed_size, sealed_rk,
                                                    supernode_size, supernode,
                                                    nonce_size, nonce);
  if (status != SGX_SUCCESS || ret < 0)
    exit(1);

  size_t challenge_size = nonce_size + supernode_size; char challenge[challenge_size];
  std::memcpy(challenge, nonce, nonce_size);
  std::memcpy(challenge+nonce_size, supernode, supernode_size);

  status = sgx_sign_message(ENCLAVE_ID, &ret, challenge_size, challenge,
              sk_size, sk, sig_size, sig);
  if (status != SGX_SUCCESS || ret < 0)
    exit(1);

  status = sgx_validate_signature(ENCLAVE_ID, &ret, options.username, sig_size, sig, pk_size, pk);
  if (status != SGX_SUCCESS || ret < 0) {
    std::cout << "Fail to validate PKI signature." << std::endl;
    exit(1);
  }

  free(sealed_rk); free(supernode);
  free(pk); free(sk);

  retrieve_nexus();
}

static void* nexus_init_new() {
  int ret;
  if (system((char*)("mkdir "+META_PATH).c_str()) < 0 || system((char*)("mkdir "+ENCR_PATH).c_str()) < 0)
    exit(1);
  else
    if (sgx_init_new_filesystem(ENCLAVE_ID, &ret, (char*)SUPERNODE_PATH.c_str()) != SGX_SUCCESS || ret < 0)
      exit(1);

  char *pk = (char*) malloc(sizeof(sgx_ec256_public_t));
  char *sk = (char*) malloc(sizeof(sgx_ec256_private_t));
  size_t pk_size = sizeof(sgx_ec256_public_t);
  size_t sk_size = sizeof(sgx_ec256_private_t);

  sgx_status_t status = sgx_create_user(ENCLAVE_ID, &ret, options.username, pk_size, pk, sk_size, sk);
  if (status != SGX_SUCCESS || ret < 0)
    exit(1);

  if (dump(options.user_pk_file, pk_size, pk) < 0 ||
      dump(options.user_sk_file, sk_size, sk) < 0)
    exit(1);

  free(sk); free(pk);
  return 0;
}

static void* nexus_init(struct fuse_conn_info *conn) {
  std::string path_token = NEXUS_DIR + "/enclave.token";
  std::string path_so = NEXUS_DIR + "/enclave.signed.so";
  int initialized = initialize_enclave(&ENCLAVE_ID, path_token, path_so);
  if (initialized < 0) {
    std::cout << "Fail to initialize enclave." << std::endl;
    exit(1);
  }

  if (options.create_fs)
    nexus_init_new();
  else
    nexus_init_existing();

  return &ENCLAVE_ID;
}

static void nexus_destroy(void* private_data) {
  int ret;
  sgx_supernode_size(ENCLAVE_ID, &ret);

  size_t rk_sealed_size = /*AES_GCM_context::size()*/44 + sizeof(sgx_sealed_data_t);
  size_t supernode_size = ret;
  char *sealed_rk = (char*) malloc(rk_sealed_size);
  char *supernode = (char*) malloc(supernode_size);

  sgx_status_t status = sgx_destroy_filesystem(ENCLAVE_ID, &ret, rk_sealed_size, sealed_rk,
                                                supernode_size, supernode);
  if (status != SGX_SUCCESS || ret < 0) {
    std::cout << "Fail to destroy the file system." << std::endl;
    exit(1);
  }
  sgx_destroy_enclave(ENCLAVE_ID);

  dump(RK_PATH, rk_sealed_size, sealed_rk);
  dump(SUPERNODE_PATH, supernode_size, supernode);
  free(sealed_rk); free(supernode);
}


static int nexus_getattr(const char *path, struct stat *stbuf) {
	memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_uid = getuid();
  stbuf->st_gid = getgid();
  stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0777;
		stbuf->st_nlink = 2;
    return 0;
	}

  int ret;
  std::string filename = get_filename(path);
  sgx_status_t status = sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());

  if (ret == EEXIST) {
    stbuf->st_mode = S_IFREG | 0777;
    stbuf->st_nlink = 1;
    sgx_file_size(ENCLAVE_ID, &ret, (char*)filename.c_str());
    stbuf->st_size = ret;
  } else {
    return -ENOENT;
  }
  return 0;
}

static int nexus_fgetattr(const char *path, struct stat *stbuf,
                   struct fuse_file_info *) {
  return nexus_getattr(path, stbuf);
}


static int nexus_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi) {
  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);

  int ret;
  sgx_ls_buffer_size(ENCLAVE_ID, &ret);
  const size_t buffer_size = ret; char *buffer = (char*) malloc(buffer_size);
  sgx_readdir(ENCLAVE_ID, &ret, BUFFER_SEPARATOR, buffer_size, buffer);
  std::vector<std::string> files = tokenize(buffer, BUFFER_SEPARATOR);
  for (auto it = files.begin(); it != files.end(); it++) {
    filler(buf, (char*)it->c_str(), NULL, 0);
  }

  free(buffer);
  return 0;
}


static int nexus_open(const char *filepath, struct fuse_file_info *) {
  std::string filename = get_filename(filepath);
  int ret;
  sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  return 0;
}

static int nexus_create(const char *filepath, mode_t mode, struct fuse_file_info *) {
  std::string filename = get_filename(filepath);
  int ret;
  sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == EEXIST)
    return -EEXIST;
  sgx_create_file(ENCLAVE_ID, &ret, (char*)filename.c_str());

  nexus_write_metadata(filename);

  return 0;
}

static int nexus_read(const char *filepath, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *) {
  std::string filename = get_filename(filepath);
  int ret;
  sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;

  sgx_read_file(ENCLAVE_ID, &ret, (char*)filename.c_str(), (long)offset, size, buf);
  return ret;
}

static int nexus_write(const char *filepath, const char *data, size_t size, off_t offset,
                struct fuse_file_info *) {
  std::string filename = get_filename(filepath);
  int ret;
  sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  sgx_write_file(ENCLAVE_ID, &ret, (char*)filename.c_str(), (long)offset, size, data);

  nexus_write_metadata(filename);
  nexus_write_encryption(filename, (long)offset, size);

  return ret;
}

static int nexus_unlink(const char *filepath) {
  std::string filename = get_filename(filepath);
  int ret;
  sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;

  sgx_unlink(ENCLAVE_ID, &ret, (char*)filename.c_str());
  delete_file(META_PATH + "/" + filename);
  return ret;
}



static struct fuse_operations nexus_oper;

int main(int argc, char **argv) {
  std::string binary_path =  get_directory(std::string(argv[0]));
  NEXUS_DIR = binary_path + "/.nexus";
  META_PATH = NEXUS_DIR + "/metadata"; ENCR_PATH = NEXUS_DIR + "/ciphers";
  RK_PATH = NEXUS_DIR + "/sealed_rk"; SUPERNODE_PATH = NEXUS_DIR + "/supernode";

  int ret;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  /* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
	options.user_pk_file = strdup((char*)(binary_path + "/ecc-256-public-key.spki").c_str());
  options.user_sk_file = strdup((char*)(binary_path + "/ecc-256-private-key.p8").c_str());

  /* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

  /* When --help is specified, first print our own file-system
	   specific help text, then signal fuse_main to show
	   additional help (by adding `--help` to the options again)
	   without usage: line (by setting argv[0] to the empty
	   string) */
	if (options.show_help) {
		assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0][0] = '\0';
	} else if (options.username == NULL && options.new_username == NULL) {
    std::cout << "Missing username." << std::endl;
    fuse_opt_free_args(&args);
    return 0;
  } else if (options.create_fs && options.username != NULL) {
    nexus_init(NULL);
    nexus_destroy(NULL);
    fuse_opt_free_args(&args);
    return 0;
  } else if (options.new_user && options.new_user_pk_file != NULL && options.new_username != NULL) {
    nexus_init(NULL);

    int ret;
    int pk_size = sizeof(sgx_ec256_public_t); char *pk = NULL;
    pk_size = load(options.new_user_pk_file, &pk);
    if (pk_size < 0)
      exit(1);

    sgx_status_t status = sgx_add_user(ENCLAVE_ID, &ret, options.new_username, pk_size, pk);
    if (status != SGX_SUCCESS || ret < 0) {
      std::cout << "Impossible to add a new user." << std::endl;
      exit(1);
    }

    nexus_destroy(NULL);
    fuse_opt_free_args(&args);
    return 0;
  }


  nexus_oper.init = nexus_init;
  nexus_oper.destroy = nexus_destroy;

  nexus_oper.getattr = nexus_getattr;
  nexus_oper.fgetattr = nexus_fgetattr;

  nexus_oper.readdir = nexus_readdir;

  nexus_oper.open = nexus_open;
  nexus_oper.create = nexus_create;
  nexus_oper.read = nexus_read;
  nexus_oper.write = nexus_write;
  nexus_oper.unlink = nexus_unlink;


  ret = fuse_main(args.argc, args.argv, &nexus_oper, NULL);
  fuse_opt_free_args(&args);
  return ret;
}
