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

#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include <curl/curl.h>


/* holder for curl fetch */
struct curl_fetch_st {
    char *payload;
    size_t size;
};


size_t curl_callback (void *contents, size_t size, size_t nmemb, void *userp);
CURLcode curl_fetch_url(CURL *ch, const char *url, struct curl_fetch_st *fetch);

json_object* lookup_json(json_object* rootObj, const char* key);
