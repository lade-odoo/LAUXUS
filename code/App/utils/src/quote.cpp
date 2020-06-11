#include "../headers/quote.hpp"

sgx_spid_t GLOBAL_SPID = {.id = { 0xE9, 0xA4, 0x40, 0x61, 0xE0, 0xB2, 0xD2, 0x8D,
                           0x46, 0xCF, 0xCE, 0x01, 0xD7, 0x14, 0x40, 0x75 }};


sgx_quote_t* sgx_generate_quote(const sgx_ec256_public_t *pk_eu, uint32_t *quote_size) {
  // https://github.com/intel/linux-sgx/issues/82
  sgx_target_info_t target_info; bzero(&target_info, sizeof(target_info));
  sgx_epid_group_id_t epid_gid; bzero(&epid_gid, sizeof(epid_gid));
  sgx_report_t report; bzero(&report, sizeof(report));
  sgx_quote_t *quote = NULL;
  int ret = -1;


  sgx_status_t sgx_status = sgx_init_quote(&target_info, &epid_gid);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to init the quote !"))
    return NULL;

  sgx_status = sgx_generate_report(ENCLAVE_ID, &ret, pk_eu, &target_info, &report);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to generate report !", ret))
    return NULL;

  sgx_status = sgx_calc_quote_size(NULL, 0, quote_size);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to compute quote size !"))
    return NULL;

  quote = (sgx_quote_t*) malloc(*quote_size); memset(quote, 0, *quote_size);
  sgx_status = sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, &GLOBAL_SPID, NULL, NULL, 0, NULL, quote, *quote_size);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to get the quote !")) {
    free(quote);
    return NULL;
  }

  return quote;
}
