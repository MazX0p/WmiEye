#ifndef SIGMARULES_H
#define SIGMARULES_H

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "cJSON.h"

#define MAX_STRING_LEN 4096

typedef struct {
    char* id;
    char* name;
    char* description;
    char* level;
    cJSON* detection;
} SigmaRule;

SigmaRule* sigmarules_load_file(const char* filename);
int sigmarules_detect(SigmaRule* sigma_rule, EVENT_RECORD* event_record);
void sigmarules_free(SigmaRule* sigma_rule);

#endif /* SIGMARULES_H */
