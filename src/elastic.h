#ifndef ELASTIC_H
#define ELASTIC_H

#include <curl/curl.h>
#include "cJSON.h"

#define ELASTIC_URL "http://localhost:9200"
#define ELASTIC_INDEX "wmi-eye"
#define ELASTIC_TYPE "_doc"

void elastic_send_alert(char* rule_name, char* event_id, char* log_name, char* message);

#endif /* ELASTIC_H */
