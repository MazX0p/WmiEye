#ifndef EVENTLOG_H
#define EVENTLOG_H

#include <windows.h>
#include <evntcons.h>
#include "sigmarules.h"

#define MAX_EVENT_DATA_SIZE 4096
#define MAX_EVENT_PAYLOAD_SIZE 65536
#define MAX_EVENT_RECORDS 16

typedef struct {
    EVENT_RECORD* event_records[MAX_EVENT_RECORDS];
    ULONG count;
} EventLogResults;

void eventlog_start();
EventLogResults eventlog_read_events();
BOOL eventlog_match_rule(EVENT_RECORD* event_record, SigmaRule* sigma_rule);

#endif /* EVENTLOG_H */
