#include <stdio.h>

#include <stdlib.h>

#include <Windows.h>

#include <winevt.h>

#include "eventlog.h"

// Function prototypes.
void printLastError(char * message);

HANDLE openEventLog(char * logname) {
  HANDLE hEventLog = OpenEventLogA(NULL, logname);
  if (hEventLog == NULL) {
    printLastError("Failed to open event log");
    exit(1);
  }
  return hEventLog;
}

void startEventMonitoring(HANDLE hEventLog, char * bookmark, EventCallback callback) {
  // Initialize the query.
  DWORD dwFlags = EVT_QUERY_DIRECTION_BACKWARD | EVT_QUERY_TOLERANCE_INFINITE;
  EVT_HANDLE hQuery = EvtQuery(NULL, NULL, "*", EVT_EVENT_CHANNEL, dwFlags);
  if (hQuery == NULL) {
    printLastError("Failed to create event query");
    exit(1);
  }

  // Set the bookmark.
  if (bookmark != NULL) {
    EVT_HANDLE hBookmark = EvtCreateBookmark(bookmark);
    if (hBookmark == NULL) {
      printLastError("Failed to create bookmark");
    } else {
      if (!EvtSeek(hEventLog, 0, hBookmark, 0, 0, NULL)) {
        printLastError("Failed to seek to bookmark");
      }
      EvtClose(hBookmark);
    }
  }

  // Start monitoring events.
  EVT_HANDLE hEvents[1];
  while (1) {
    if (EvtNext(hQuery, 1, hEvents, INFINITE, 0, NULL)) {
      // Process the event.
      callback(hEvents[0]);
      EvtClose(hEvents[0]);
    } else if (GetLastError() == ERROR_NO_MORE_ITEMS) {
      // No more events.
      break;
    } else {
      // Error occurred.
      printLastError("Failed to get next event");
      break;
    }
  }

  // Clean up.
  EvtClose(hQuery);
}

char * getEventProperty(EVT_HANDLE hEvent, EVT_EVENT_PROPERTY_ID property_id) {
  DWORD buffer_size = 0;
  DWORD property_size = 0;
  char * buffer = NULL;
  if (!EvtRender(NULL, hEvent, property_id, buffer_size, buffer, & property_size, & buffer_size)) {
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      buffer = (char * ) malloc(buffer_size);
      if (!EvtRender(NULL, hEvent, property_id, buffer_size, buffer, & property_size, & buffer_size)) {
        printLastError("Failed to render event property");
        free(buffer);
        buffer = NULL;
      }
    } else {
      printLastError("Failed to render event property");
    }
  }
  return buffer;
}

char * getEventMessage(EVT_HANDLE hEvent) {
  return getEventProperty(hEvent, EvtEventMessageId);
}

char * getEventLevel(EVT_HANDLE hEvent) {
  return getEventProperty(hEvent, EvtEventLevel);
}

char * getEventTask(EVT_HANDLE hEvent) {
  return getEventProperty(hEvent, EvtEventTaskDisplayName);
}

char * getEventOpcode(EVT_HANDLE hEvent) {
  return getEventProperty(hEvent, EvtEventOpcode);
}

char * getEventKeywords(EVT_HANDLE hEvent) {
  return getEventProperty(hEvent, EvtEventKeywords);
}

char * getEventChannel(EVT_HANDLE hEvent) {
  return getEventProperty(hEvent, EvtEventChannelName);
}

char * getEventProvider(EVT_HANDLE hEvent) {
  return getEventProperty(hEvent, EvtEventProviderName);
}

char * getEventTimeCreated(EVT_HANDLE hEvent) {
  char * time_created = NULL;
  SYSTEMTIME st;
  FILETIME ft;
  DWORD buffer_size = sizeof(SYSTEMTIME);
  if (EvtGetEventMetadataProperty(hEvent, EventMetadataEventTimestamp, buffer_size, & st, & buffer_size)) {
    SystemTimeToFileTime( & st, & ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    time_created = (char * ) malloc(21);
    sprintf_s(time_created, 21, "%016I64X", uli.QuadPart);
  } else {
    printLastError("Failed to get event time created");
  }
  return time_created;
}

char * getEventID(EVT_HANDLE hEvent) {
  char * event_id = NULL;
  DWORD event_id_val = 0;
  DWORD buffer_size = sizeof(DWORD);
  if (EvtGetEventMetadataProperty(hEvent, EventMetadataEventID, buffer_size, & event_id_val, & buffer_size)) {
    event_id = (char * ) malloc(11);
    sprintf_s(event_id, 11, "%u", event_id_val);
  } else {
    printLastError("Failed to get event ID");
  }
  return event_id;
}

char * getEventComputer(EVT_HANDLE hEvent) {
  return getEventProperty(hEvent, EvtEventComputerName);
}

char * getEventUser(EVT_HANDLE hEvent) {
  return getEventProperty(hEvent, EvtEventUserSid);
}

char * getEventObjectValueByKey(EventObject * event_obj, char * key) {
  // Search for the key in the object's properties.
  for (int i = 0; i < event_obj -> num_properties; i++) {
    EventProperty property = event_obj -> properties[i];
    if (strcmp(property.key, key) == 0) {
      // Return the value of the property.
      return property.value;
    }
  }
  // Key not found.
  return NULL;
}

void printLastError(char * message) {
  LPSTR message_buffer = NULL;
  DWORD error_code = GetLastError();
  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) & message_buffer, 0, NULL);
  printf("%s: %s\n", message, message_buffer);
  LocalFree(message_buffer);
}
