#include <stdio.h>

#include <stdlib.h>

#include <curl/curl.h>

#include <cjson/cJSON.h>

#include "elastic.h"

// Function prototypes.
size_t writeResponseCallback(char * ptr, size_t size, size_t nmemb, void * userdata);
void printCurlError(CURL * curl, CURLcode res);

void sendAlertToElastic(EventObject * event_obj, SigmaRule * rule) {
  // Create the JSON document.
  cJSON * json_root = cJSON_CreateObject();
  cJSON * json_event = cJSON_AddObjectToObject(json_root, "event");
  cJSON_AddStringToObject(json_event, "provider", "eventlog-sigma");
  cJSON_AddStringToObject(json_event, "logsource", event_obj -> logsource);
  cJSON_AddStringToObject(json_event, "message", event_obj -> message);
  cJSON_AddStringToObject(json_event, "level", event_obj -> level);
  cJSON_AddStringToObject(json_event, "task", event_obj -> task);
  cJSON_AddStringToObject(json_event, "opcode", event_obj -> opcode);
  cJSON_AddStringToObject(json_event, "keywords", event_obj -> keywords);
  cJSON_AddStringToObject(json_event, "channel", event_obj -> channel);
  cJSON_AddStringToObject(json_event, "provider_name", event_obj -> provider_name);
  cJSON_AddStringToObject(json_event, "time_created", event_obj -> time_created);
  cJSON_AddStringToObject(json_event, "event_id", event_obj -> event_id);
  cJSON_AddStringToObject(json_event, "computer", event_obj -> computer);
  cJSON_AddStringToObject(json_event, "user", event_obj -> user);
  cJSON * json_rule = cJSON_AddObjectToObject(json_root, "rule");
  cJSON_AddStringToObject(json_rule, "description", rule -> description);
  cJSON_AddStringToObject(json_rule, "status", rule -> status);
  cJSON_AddStringToObject(json_rule, "author", rule -> author);
  cJSON_AddStringToObject(json_rule, "references", rule -> references);
  cJSON_AddStringToObject(json_rule, "tags", rule -> tags);
  cJSON * json_detection = cJSON_AddObjectToObject(json_rule, "detection");
  for (int i = 0; i < rule -> num_kvp; i++) {
    KeyValue kvp = rule -> detection[i];
    cJSON_AddStringToObject(json_detection, kvp.key, kvp.value);
  }
  char * json_str = cJSON_Print(json_root);

  // Set up the HTTP request.
  CURL * curl = curl_easy_init();
  if (curl == NULL) {
    printf("Failed to initialize cURL\n");
    cJSON_Delete(json_root);
    return;
  }
  curl_easy_setopt(curl, CURLOPT_URL, ELASTICSEARCH_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 1 L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeResponseCallback);

  // Set up the HTTP headers.
  struct curl_slist * headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "User-Agent: eventlog-sigma");
  headers = curl_slist_append(headers, "Accept: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  // Send the HTTP request.
  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    printCurlError(curl, res);
  }

  // Clean up.
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  cJSON_Delete(json_root);
}

size_t writeResponseCallback(char * ptr, size_t size, size_t nmemb, void * userdata) {
  // Ignore the response body.
  return size * nmemb;
}

void printCurlError(CURL * curl, CURLcode res) {
  printf("cURL error: %s\n", curl_easy_strerror(res));
}
