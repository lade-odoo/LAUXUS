#ifndef __LAUXUS_HPP__
#define __LAUXUS_HPP__

#include <stdio.h>
#include <iostream>

#include "../../../flag.h"
#if EMULATING
#   include "../../../tests/SGX_Emulator/sgx_error.hpp"
#   include "../../../tests/SGX_Emulator/Enclave_u.hpp"
#else
#   include "sgx_urts.h"
#   include "sgx_error.h"
#   include "Enclave_u.h"
#endif

#include "base64.h"
#include "quote.hpp"
#include "serialisation.hpp"
#include "../../sgx_utils/sgx_utils.h"

using namespace std;

extern sgx_enclave_id_t ENCLAVE_ID;
extern string NEXUS_DIR;
extern string CONTENT_DIR, META_DIR, AUDIT_DIR, QUOTE_DIR;
extern string RK_PATH, ARK_PATH, SUPERNODE_PATH;



int init_enclave();
void destroy_enclave();


int lauxus_new();
int lauxus_load();
int lauxus_login(string sk_u_path, string str_uuid);
int lauxus_destroy();

int lauxus_create_quote(string sk_u_path, string sk_eu_path, string pk_eu_path, string user_uuid);
sgx_ec256_public_t *lauxus_verify_quote(string pk_u_path, string user_uuid);
int lauxus_get_shared_rk(string sk_u_path, string pk_o_path, string other_user_uuid);

int lauxus_new_keys(string sk_u_path, string pk_u_path);

int lauxus_add_user(string username, string pk_u_path);
int lauxus_remove_user(string str_uuid);
int lauxus_edit_user_entitlement(string path, string str_uuid,
              int owner_right, int read_right, int write_right, int exec_right);


#endif /*__LAUXUS_HPP__*/
