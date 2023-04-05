#include <stdio.h>

#include <stdlib.h>

#include <Windows.h>

#include <Evt.h>

#include <yaml.h>

#include "sigmarules.h"

#include "eventlog.h"

#include "elastic.h"

// Function prototypes.
void parseConfigFile(char * config_file, SigmaRule ** rules, int * num_rules, ElasticConfig * elastic_config);
void checkSigmaRules(EVT_HANDLE hEvent, SigmaRule * rules, int num_rules, ElasticConfig elastic_config);

int main(int argc, char * argv[]) {
  if (argc != 2) {
    printf("Usage: %s <config_file>\n", argv[0]);
    return 1;
  }

  // Parse the configuration file.
  SigmaRule * rules;
  int num_rules;
  ElasticConfig elastic_config;
  parseConfigFile(argv[1], & rules, & num_rules, & elastic_config);

  // Open the event log.
  EVT_HANDLE hEventLog = openEventLog();

  // Start monitoring events.
  EVT_HANDLE hEvents[1];
  hEvents[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
  while (TRUE) {
    // Wait for events to become available.
    WaitForMultipleObjects(1, hEvents, FALSE, INFINITE);

    // Get the next available event.
    EVT_HANDLE hEvent;
    while ((hEvent = getNextEvent(hEventLog)) != NULL) {
      // Check if the event matches any Sigma rules.
      checkSigmaRules(hEvent, rules, num_rules, elastic_config);

      // Close the event.
      EvtClose(hEvent);
    }

    // Reset the event object.
    ResetEvent(hEvents[0]);
  }

  // Cleanup.
  freeSigmaRules(rules, num_rules);
  EvtClose(hEventLog);

  return 0;
}

void parseConfigFile(char * config_file, SigmaRule ** rules, int * num_rules, ElasticConfig * elastic_config) {
  // Open the configuration file.
  FILE * fp;
  if (fopen_s( & fp, config_file, "r") != 0) {
    printf("Failed to open configuration file.\n");
    exit(1);
  }

  // Parse the configuration file as YAML.
  yaml_parser_t parser;
  yaml_event_t event;
  int done = 0;
  int error = 0;
  char * key = NULL;
  SigmaRule * rule = NULL;
  int rule_num = 0;
  int in_elastic = 0;
  while (!done) {
    // Get the next event from the parser.
    if (!yaml_parser_parse( & parser, & event)) {
      printf("Error parsing configuration file.\n");
      error = 1;
      break;
    }

    // Process the event.
    switch (event.type) {
    case YAML_SCALAR_EVENT:
      // Get the key or value of a scalar.
      if (key == NULL) {
        // This is a key.
        key = strdup((char * ) event.data.scalar.value);
      } else {
        // This is a value.
        if (strcmp(key, "sigma_rules_directory") == 0) {
          // Load the Sigma rules from the specified directory.
          * rules = loadSigmaRulesFromDirectory((char * ) event.data.scalar.value, num_rules);
        } else if (strcmp(key, "elastic_host") == 0) {
          // Set the Elasticsearch hostname.
          strcpy_s(elastic_config -> host, sizeof(elastic_config -> host), (char * ) event.data.scalar.value);
        } else if (strcmp(key, "elastic_port") == 0) {
          // Set the Elasticsearch port number.
          elastic_config -> port = atoi((char * ) event.data.scalar.value);
        } else if (strcmp(key, "elastic_index") == 0) {
          // Set the Elasticsearch index name.
          strcpy_s(elastic_config -> index, sizeof(elastic_config -> index), (char * ) event.data.scalar.value);
        } else {
          // This is a key for a Sigma rule.
          if (strcmp(key, "title") == 0) {
            // Create a new Sigma rule.
            rule = (SigmaRule * ) realloc( * rules, (rule_num + 1) * sizeof(SigmaRule));
            memset( & rule[rule_num], 0, sizeof(SigmaRule));
            rule[rule_num].title = strdup((char * ) event.data.scalar.value);
            rule_num++;
          } else if (rule != NULL) {
            // Add the key-value pair to the Sigma rule.
            addKeyValuePairToSigmaRule(rule, key, (char * ) event.data.scalar.value);
          }
        }

        // Reset the key.
        free(key);
        key = NULL;
      }
      break;

    case YAML_MAPPING_START_EVENT:
      // This is the start of a new mapping.
      if (strcmp(key, "sigma_rules") == 0) {
        // We're now processing Sigma rules.
        in_elastic = 0;
      } else if (strcmp(key, "elastic_config") == 0) {
        // We're now processing Elasticsearch configuration.
        in_elastic = 1;
      }
      break;

    case YAML_MAPPING_END_EVENT:
      // This is the end of a mapping.
      if (in_elastic) {
        // We're now finished processing Elasticsearch configuration.
        in_elastic = 0;
      } else if (rule != NULL) {
        // We're now finished processing a Sigma rule.
        rule = NULL;
      }
      break;

    case YAML_SEQUENCE_START_EVENT:
      // This is the start of a new sequence.
      break;

    case YAML_SEQUENCE_END_EVENT:
      // This is the end of a sequence.
      break;

    case YAML_STREAM_END_EVENT:
      // This is the end of the YAML stream.
      done = 1;
      break;

    default:
      // Ignore all other events.
      break;
    }

    // Free the event resources.
    yaml_event_delete( & event);
  }

  // Clean up the parser.
  yaml_parser_delete( & parser);

  // Close the configuration file.
  fclose(fp);

  // Check for errors.
  if (error) {
    exit(1);
  }
}

void checkSigmaRules(EVT_HANDLE hEvent, SigmaRule * rules, int num_rules, ElasticConfig elastic_config) {
  // Render the event as an XML string.
  LPWSTR pRenderedXml = NULL;
  EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, & pRenderedXml, NULL);
  // Parse the XML string as an event object.
  xmlDocPtr doc = xmlReadMemory((const char * ) pRenderedXml, wcslen(pRenderedXml) * sizeof(WCHAR), NULL, NULL, 0);
  xmlNodePtr node = xmlDocGetRootElement(doc);
  EventObject event_obj;
  memset( & event_obj, 0, sizeof(EventObject));
  parseEventXmlNode(node, & event_obj);

  // Check the event against each Sigma rule.
  for (int i = 0; i < num_rules; i++) {
    if (matchSigmaRule( & event_obj, & rules[i])) {
      // The event matches the Sigma rule. Send an alert to Elasticsearch
      sendAlertToElasticsearch( & event_obj, elastic_config);
    }
  }

  // Clean up.
  free(pRenderedXml);
  xmlFreeDoc(doc);
  freeEventObject( & event_obj);
}
