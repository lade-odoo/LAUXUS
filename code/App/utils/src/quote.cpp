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

sgx_ec256_public_t *sgx_verify_quote(uint32_t b64_quote_size, const uint8_t *b64_quote) {
  string str_b64_quote((char*)b64_quote);
  CURL *ch;
  CURLcode rcode;
  json_object *json;
  enum json_tokener_error jerr = json_tokener_success;

  struct curl_fetch_st curl_fetch;
  struct curl_fetch_st *cf = &curl_fetch;
  struct curl_slist *headers = NULL;

  if ((ch = curl_easy_init()) == NULL)
    return NULL;

  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "Ocp-Apim-Subscription-Key: 783ce5d88b6647d2a69db3f5bd6234db");

  json = json_object_new_object();
  json_object_object_add(json, "isvEnclaveQuote", json_object_new_string(str_b64_quote.c_str()));

  curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(ch, CURLOPT_POSTFIELDS, json_object_to_json_string(json));

  rcode = curl_fetch_url(ch, QUOTE_VERIFY_URL.c_str(), cf);
  curl_easy_cleanup(ch);
  curl_slist_free_all(headers);
  json_object_put(json);

  // check CURL errors
  if (rcode != CURLE_OK || cf->size < 1 || cf->payload == NULL)
    return NULL;

  // Parse response to JSON
  json = json_tokener_parse_verbose(cf->payload, &jerr);
  free(cf->payload);
  if (jerr != json_tokener_success)
    return NULL;
  else if (lookup_json(json, "statusCode") != NULL || lookup_json(json, "isvEnclaveQuoteBody") == NULL)
    return NULL;


  // Retrieve pk_eu from inside the enclave
  const char *b64_quoteBody = json_object_get_string(lookup_json(json, "isvEnclaveQuoteBody"));

  // Translate quoteBody from base64 to hex
  int quoteBody_size = Base64decode_len(b64_quoteBody);
  uint8_t quoteBody[quoteBody_size];
  if (Base64decode((char*)quoteBody, b64_quoteBody) < 0)
    return NULL;

  sgx_ec256_public_t *pk_eo = (sgx_ec256_public_t*) malloc(sizeof(sgx_ec256_public_t));
  memcpy(pk_eo, quoteBody+quoteBody_size-sizeof(sgx_ec256_public_t), sizeof(sgx_ec256_public_t));

  json_object_put(json);
  return pk_eo;
}
