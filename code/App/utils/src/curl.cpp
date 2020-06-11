/**
 * License:
 *
 * This code is licensed under MIT license
 * https://opensource.org/licenses/MIT
 *
 * Source:
 *
 * https://gist.github.com/leprechau/e6b8fef41a153218e1f4
 *
 */

#include "../headers/curl.hpp"

/* callback for curl fetch */
size_t curl_callback (void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;                             /* calculate buffer size */
  struct curl_fetch_st *p = (struct curl_fetch_st *) userp;   /* cast pointer to fetch struct */

  /* expand buffer */
  p->payload = (char *) realloc(p->payload, p->size + realsize + 1);

  /* check buffer */
  if (p->payload == NULL) {
    /* this isn't good */
    fprintf(stderr, "ERROR: Failed to expand buffer in curl_callback");
    /* free buffer */
    free(p->payload);
    /* return */
    return 1;
  }

  /* copy contents to buffer */
  memcpy(&(p->payload[p->size]), contents, realsize);

  /* set new buffer size */
  p->size += realsize;

  /* ensure null termination */
  p->payload[p->size] = 0;

  /* return size */
  return realsize;
}

/* fetch and return url body via curl */
CURLcode curl_fetch_url(CURL *ch, const char *url, struct curl_fetch_st *fetch) {
  CURLcode rcode;                   /* curl result code */

  /* init payload */
  fetch->payload = (char *) calloc(1, sizeof(fetch->payload));

  /* check payload */
  if (fetch->payload == NULL) {
      /* log error */
      fprintf(stderr, "ERROR: Failed to allocate payload in curl_fetch_url");
      /* return error */
      return CURLE_FAILED_INIT;
  }

  /* init size */
  fetch->size = 0;

  /* set url to fetch */
  curl_easy_setopt(ch, CURLOPT_URL, url);

  /* set calback function */
  curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_callback);

  /* pass fetch struct pointer */
  curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) fetch);

  /* set timeout */
  curl_easy_setopt(ch, CURLOPT_TIMEOUT, 15);

  /* enable location redirects */
  curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1L);

  /* set maximum allowed redirects */
  curl_easy_setopt(ch, CURLOPT_MAXREDIRS, 1);

  /* fetch the url */
  rcode = curl_easy_perform(ch);

  /* return */
  return rcode;
}


json_object* lookup_json(json_object* rootObj, const char* key) {
  json_object* returnObj;
  if (json_object_object_get_ex(rootObj, key, &returnObj))
    return returnObj;
  return NULL;
}
