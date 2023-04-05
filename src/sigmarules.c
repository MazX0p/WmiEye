#include <stdio.h>

#include <stdlib.h>

#include <Windows.h>

#include <shlwapi.h>

#include <yaml.h>

#include "sigmarules.h"

// Function prototypes.
void parseSigmaRuleNode(xmlNodePtr node, SigmaRule * rule);

SigmaRule * loadSigmaRulesFromDirectory(char * directory_path, int * num_rules) {
  // Allocate an array to hold the Sigma rules.
  SigmaRule * rules = NULL;
  * num_rules = 0;

  // Open the directory.
  WIN32_FIND_DATA find_data;
  HANDLE hFind = FindFirstFileA(directory_path, & find_data);
  if (hFind != INVALID_HANDLE_VALUE) {
    do {
      // Ignore directories and hidden files.
      if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ||
        find_data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) {
        continue;
      }

      // Construct the path to the file.
      char file_path[MAX_PATH];
      snprintf(file_path, MAX_PATH, "%s\\%s", directory_path, find_data.cFileName);

      // Load the Sigma rule from the file.
      SigmaRule rule;
      loadSigmaRuleFromFile(file_path, & rule);

      // Add the Sigma rule to the array.
      rules = (SigmaRule * ) realloc(rules, ( * num_rules + 1) * sizeof(SigmaRule));
      memcpy( & rules[ * num_rules], & rule, sizeof(SigmaRule));
      ( * num_rules) ++;
    } while (FindNextFileA(hFind, & find_data));
    FindClose(hFind);
  }

  return rules;
}

void loadSigmaRuleFromFile(char * file_path, SigmaRule * rule) {
  // Open the file.
  FILE * fp;
  if (fopen_s( & fp, file_path, "r") != 0) {
    printf("Failed to open Sigma rule file: %s\n", file_path);
    exit(1);
  }

  // Read the file as YAML.
  yaml_parser_t parser;
  yaml_event_t event;
  int done = 0;
  int error = 0;
  char * key = NULL;
  while (!done) {
    // Get the next event from the parser.
    if (!yaml_parser_parse( & parser, & event)) {
      printf("Error parsing Sigma rule file: %s\n", file_path);
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
        if (strcmp(key, "title") == 0) {
          // Set the title of the Sigma rule.
          rule -> title = strdup((char * ) event.data.scalar.value);
        } else if (strcmp(key, "description") == 0) {
          // Set the description of the Sigma rule.
          rule -> description = strdup((char * ) event.data.scalar.value);
        } else if (strcmp(key, "status") == 0) {
          // Set the status of the Sigma rule.
          rule -> status = strdup((char * ) event.data.scalar.value);
        } else if (strcmp(key, "author") == 0) {
          // Set the author of the Sigma rule.
          rule -> author = strdup((char * ) event.data.scalar.value);
        } else if (strcmp(key, "references") == 0) {
          // Set the references of the Sigma rule.
          rule -> references = strdup((char * ) event.data.scalar.value);
        } else if (strcmp(key, "tags") == 0) {
          // Set the tags of the Sigma rule.
          rule -> tags = strdup((char * ) event.data.scalar.value);
        } else if (strcmp(key, "logsource") == 0) {
          // Set the logsource of the Sigma rule.
          rule -> logsource = strdup((char * ) event.data.scalar.value);
        } else if (strcmp(key, "detection") == 0) {
          // Parse the detection section of the Sigma rule.
          parseSigmaRuleNode(event.data.mapping_start.content, rule);
        }
        // Reset the key.
        free(key);
        key = NULL;
      }
      break;

    case YAML_MAPPING_START_EVENT:
      // This is the start of a new mapping.
      break;

    case YAML_MAPPING_END_EVENT:
      // This is the end of a mapping.
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

  // Close the file.
  fclose(fp);

  // Check for errors.
  if (error) {
    exit(1);
  }
}

void addKeyValuePairToSigmaRule(SigmaRule * rule, char * key, char * value) {
  if (strcmp(key, "description") == 0) {
    // Set the description of the Sigma rule.
    rule -> description = strdup(value);
  } else if (strcmp(key, "status") == 0) {
    // Set the status of the Sigma rule.
    rule -> status = strdup(value);
  } else if (strcmp(key, "author") == 0) {
    // Set the author of the Sigma rule.
    rule -> author = strdup(value);
  } else if (strcmp(key, "references") == 0) {
    // Set the references of the Sigma rule.
    rule -> references = strdup(value);
  } else if (strcmp(key, "tags") == 0) {
    // Set the tags of the Sigma rule.
    rule -> tags = strdup(value);
  } else if (strcmp(key, "logsource") == 0) {
    // Set the logsource of the Sigma rule.
    rule -> logsource = strdup(value);
  } else {
    // Add the key-value pair to the detection section of the Sigma rule.
    KeyValue * kvp = (KeyValue * ) realloc(rule -> detection, (rule -> num_kvp + 1) * sizeof(KeyValue));
    kvp[rule -> num_kvp].key = strdup(key);
    kvp[rule -> num_kvp].value = strdup(value);
    rule -> detection = kvp;
    rule -> num_kvp++;
  }
}

int matchSigmaRule(EventObject * event_obj, SigmaRule * rule) {
  // Check the logsource of the event against the logsource of the Sigma rule.
  if (rule -> logsource != NULL && strcasecmp(event_obj -> logsource, rule -> logsource) != 0) {
    return 0;
  }
  // Check each key-value pair in the detection section of the Sigma rule against the event
  for (int i = 0; i < rule -> num_kvp; i++) {
    KeyValue kvp = rule -> detection[i];
    char * value = getEventObjectValueByKey(event_obj, kvp.key);
    if (value == NULL || strcmp(value, kvp.value) != 0) {
      return 0;
    }
  }

  // All checks passed. The event matches the Sigma rule.
  return 1;
}
void parseSigmaRuleNode(xmlNodePtr node, SigmaRule * rule) {
  // Parse each child node of the mapping.
  for (xmlNodePtr child = node; child != NULL; child = child -> next) {
    // Ignore non-element nodes.
    if (child -> type != XML_ELEMENT_NODE) {
      continue;
    }
    // Get the key and value of the node.
    char * key = (char * ) child -> name;
    char * value = (char * ) xmlNodeGetContent(child);

    // Add the key-value pair to the detection section of the Sigma rule.
    addKeyValuePairToSigmaRule(rule, key, value);

    // Free the value.
    xmlFree(value);
  }
}
