![IMG_5999](https://user-images.githubusercontent.com/54814433/230443098-5a1a5062-98a3-4cf9-aac9-9050eccbab8e.JPG)

# WmiEye

WmiEye is a C program that monitors the Windows Management Instrumentation (WMI) event logs for any events that match Sigma rules and sends alerts to Elasticsearch. The program is designed to run in the background and can be used for threat detection and response.

The program reads Sigma rules from `JSON` or `YMAL` files in the `sigmarules` directory and compares them with WMI event log entries. If there is a match between an event log entry and a Sigma rule, the program sends an alert to Elasticsearch with the event and rule information. The program also uses bookmarks to keep track of the last event processed and resumes monitoring after a restart.

## Features

The main features of the WmiEye program are:

- Reads Sigma rules from `JSON` or `YMAL` files in the `sigmarules` directory.
- Monitors the WMI event logs for any events that match the Sigma rules.
- Sends alerts to Elasticsearch with the event and rule information.
- Uses bookmarks to keep track of the last event processed and resume monitoring after a restart.
- Includes a `config.h` file for easy configuration.

## Requirements

To build and run the WmiEye program, you need the following:

- Windows operating system
- Microsoft Visual Studio (tested with version 2019)
- libcurl library (tested with version 7.78.0)
- libcjson library (tested with version 1.7.14)

## Installation

To install the WmiEye program, follow these steps:

1. Clone the repository to your local machine using the following command: `git clone https://github.com/MazX0p/WmiEye.git`
2. Open the solution file `WmiEye.sln` in Visual Studio.
3. Build the solution.
4. Install the libcurl and libcjson libraries. You can download the libraries from the following links:
- [libcurl](https://curl.se/download.html)
- [libcjson](https://github.com/DaveGamble/cJSON/releases)
5. Copy the `libcurl.dll` and `libcjson.dll` files to the same directory as the executable file.
6. Run the program with administrator privileges.

## Usage

To use the WmiEye program, follow these steps:

1. Create a new `JSON` or `YAML` file in the `sigmarules` directory on the root path of the WmiEye with the following format:
```json
{
    "title": "Rule Title",
    "description": "Rule Description",
    "status": "Rule Status",
    "author": "Rule Author",
    "references": ["Reference 1", "Reference 2"],
    "tags": ["Tag 1", "Tag 2"],
    "logsource": "windows",
    "detection": {
        "condition": "Rule Condition"
    }
}
```
```yaml
title: Detect PowerShell Download
description: Detects a PowerShell download using the WinEventLog provider
status: experimental
author: John Doe
references:
  - https://example.com
logsource:
  provider: WinEventLog
  product: PowerShell
  eventid: 4104
condition: '"https://" in event_data'
output:
  title: PowerShell Download
  description: A PowerShell download was detected.
  fields:
    - name: url
      expression: event_data.url
```
Replace the fields with appropriate values for your rule.

2. Edit the config.h file with the appropriate settings for your environment, such as the name of the WMI event log to monitor and the URL of the Elasticsearch server to send alerts to.

3. Run the program with administrator privileges.

```sh
WmiEye.exe <config_file>
```
or put the config file on root directory.

The program will read the Sigma rules from the sigmarules directory and monitor the WMI event logs for any events that match the rules. If a match is found, the program sends an alert to Elasticsearch with the event and rule information.

## Example
Here's an example Sigma rule for detecting a malicious PowerShell command:

```json
{
    "title": "Malicious PowerShell Command",
    "description": "Detects a malicious PowerShell command",
    "status": "experimental",
    "author": "John Doe",
    "references": ["https://example/blog/post1"],
    "tags": ["powershell", "malware"],
    "logsource": "windows",
    "detection": {
        "condition": "eventid:4103 and powershell_command:*downloadstring*"
    }
}
```
To add this rule to the program, save it as a file named `rule1.json` in the sigmarules directory.

## Configuration
The WmiEye program can be configured using the config.h file. Here are the available options:

- LOG_NAME: The name of the WMI event log to monitor. The default value is `Microsoft-Windows-WMI-Activity/Operational`. 
- ELASTICSEARCH_URL: The URL of the Elasticsearch server to send alerts to. The default value is `http://localhost:9200`. 
- BOOKMARK_FILE: The path of the bookmark file to use for event monitoring. The default value is `bookmarks.dat`. Set to `NULL` to disable bookmarks. 

## Limitations

The WmiEye program has a few limitations that you should be aware of:

The program only monitors the WMI event logs for events that match Sigma rules. It does not perform any other types of monitoring, such as network traffic or file system activity.
The program relies on Sigma rules to detect threats. If a threat is not covered by a Sigma rule, the program will not detect it.
The program may generate a high volume of alerts if there are many events that match the Sigma rules. You should configure Elasticsearch to handle this volume of data.

## Monitoring Multiple WMI Event Logs

By default, WmiEye monitors the `Microsoft-Windows-WMI-Activity/Operational` event log for WMI events. If you want to monitor other event logs as well, you can modify the `LOG_NAME parameter` in the `config.h` file. For example, if you want to monitor both the Security and System event logs, you can set the `LOG_NAME` parameter to `Security,System`.

## Using Sigma Rules from a Directory

In addition to using Sigma rules from individual JSON files, you can also use Sigma rules from a directory. To do this, simply save your Sigma rules in the sigmarules directory with the `.json` extension. WmiEye will automatically read all JSON files in the directory and use them for monitoring.

## Disabling Bookmarks

If you don't want WmiEye to use bookmarks to keep track of the last event processed, you can set the `BOOKMARK_FILE` parameter in the `config.h` file to `NULL`. This will disable bookmarks and WmiEye will start monitoring events from the beginning of the event log each time it is run.

## Using a Different Elasticsearch Server

If you want to send alerts to an Elasticsearch server other than the default `http://localhost:9200` you can modify the `ELASTICSEARCH_URL` parameter in the `config.h` file. For example, if your Elasticsearch server is running on a different port, you can set the `ELASTICSEARCH_URL` parameter to `http://localhost:9201`.

## Advantages of WmiEye and Why Use It if You Have a SIEM Solution?

### Advantages of WmiEye

- WmiEye is lightweight and easy to deploy. It is a standalone program that runs in the background and does not require a lot of system resources. This makes it ideal for environments where a full SIEM solution may be too resource-intensive or complex.
- WmiEye uses Sigma rules, which are easy to create and modify. This makes it easy to add new threat detection capabilities to the program without having to write custom code. Additionally, Sigma rules can be shared across different security tools and platforms, making it easier to collaborate with other security teams and organizations.
- WmiEye can be integrated with Elasticsearch for alerting and analysis. Elasticsearch is a powerful tool for searching and analyzing large volumes of data, which makes it ideal for threat hunting and incident response. By integrating WmiEye with Elasticsearch, you can quickly identify and respond to threats in your environment.
- WmiEye can monitor specific WMI event logs for threats. This makes it more targeted and efficient than a SIEM solution, which may monitor a wide range of events and logs. Additionally, WmiEye can be customized to monitor specific WMI event logs and filter out noise, which can reduce the number of false positives and improve the accuracy of threat detection.

### Why Use WmiEye if You Have a SIEM Solution?

While a SIEM solution is a powerful tool for threat detection and response, there are several reasons why you may want to consider using WmiEye in addition to your SIEM solution:

- WmiEye can be used to monitor specific event logs for threats. This makes it more targeted and efficient than a SIEM solution, which may monitor a wide range of events and logs. Additionally, WmiEye can be customized to monitor specific WMI event logs and filter out noise, which can reduce the number of false positives and improve the accuracy of threat detection.
- WmiEye uses Sigma rules, which are easy to create and modify. This makes it easy to add new threat detection capabilities to the program without having to write custom code. Additionally, Sigma rules can be shared across different security tools and platforms, making it easier to collaborate with other security teams and organizations.
- WmiEye is lightweight and easy to deploy. It can be used in environments where a full SIEM solution may be too resource-intensive or complex. Additionally, WmiEye can be deployed on specific endpoints or servers, which can improve the visibility and accuracy of threat detection.
- WmiEye can be used as a complementary tool to your SIEM solution. It can help you identify threats that may be missed by your SIEM solution and provide additional context for analysis and response. Additionally, WmiEye can be used to validate alerts generated by your SIEM solution, which can reduce the number of false positives and improve the efficiency of incident response.

Overall, WmiEye is a valuable tool for threat detection and response in Windows environments. It is easy to use, flexible, and can be integrated with Elasticsearch for alerting and analysis. Whether you have a SIEM solution or not, WmiEye can help you improve your threat detection and response capabilities and stay one step ahead of potential attackers.

## Log matched events to a local file

One potential function that could be added to WmiEye is the ability to log matched events to a local file for further analysis. This would allow security analysts to review events that have triggered Sigma rules in real-time, without the need to query Elasticsearch or the Windows Event Log directly.

To implement this functionality, you could add a command-line option that specifies the location of the log file, and modify the checkSigmaRules function to write matching events to the file when a match is found. You could also include an option to limit the number of events written to the file, to prevent it from growing too large.

Here's an example of how the new command-line option could be added to the existing code:

```c
int main(int argc, char *argv[]) {
    // ...

    char *log_file = NULL;
    int max_log_events = -1;

    // Parse command-line options
    int opt;
    while ((opt = getopt(argc, argv, "l:m:")) != -1) {
        switch (opt) {
        case 'l':
            log_file = optarg;
            break;
        case 'm':
            max_log_events = atoi(optarg);
            break;
        default:
            printf("Usage: %s [-l log_file] [-m max_log_events] <config_file>\n", argv[0]);
            return 1;
        }
    }

    // ...

    // Open the log file for writing
    FILE *log_fp = NULL;
    if (log_file != NULL) {
        if (fopen_s(&log_fp, log_file, "a") != 0) {
            printf("Failed to open log file.\n");
            exit(1);
        }
    }

    // Start monitoring events
    EVT_HANDLE hEvents[1];
    hEvents[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
    int log_event_count = 0;
    while (TRUE) {
        // Wait for events to become available
        WaitForMultipleObjects(1, hEvents, FALSE, INFINITE);

        // Get the next available event
        EVT_HANDLE hEvent;
        while ((hEvent = getNextEvent(hEventLog)) != NULL) {
            // Check if the event matches any Sigma rules
            checkSigmaRules(hEvent, rules, num_rules, elastic_config, log_fp, &log_event_count, max_log_events);

            // Close the event
            EvtClose(hEvent);
        }

        // Reset the event object
        ResetEvent(hEvents[0]);
    }

    // Cleanup
    freeSigmaRules(rules, num_rules);
    EvtClose(hEventLog);

    if (log_fp != NULL) {
        fclose(log_fp);
    }

    return 0;
}

void checkSigmaRules(EVT_HANDLE hEvent, SigmaRule *rules, int num_rules, ElasticConfig elastic_config, FILE *log_fp, int *log_event_count, int max_log_events) {
    // ...

    // Check the event against each Sigma rule
    for (int i = 0; i < num_rules; i++) {
        if (matchSigmaRule(&event_obj, &rules[i])) {
            // The event matches the Sigma rule. Send an alert to Elasticsearch and write to the log file.
            sendAlertToElasticsearch(&event_obj, elastic_config);

            if (log_fp != NULL) {
                writeEventToLogFile(log_fp, &event_obj);
                (*log_event_count)++;

                // Check if we've reached the maximum number of events to log
                if (max_log_events > 0 && (*log_event_count) >= max_log_events) {
                    fclose(log_fp);
                    log_fp = NULL;
                    break;
                }
           
```

## Conclusion

WmiEye is a powerful tool for detecting threats in the WMI event logs using Sigma rules. It is easy to configure and use, and can be integrated with Elasticsearch for alerting and analysis. By using WmiEye in your environment, you can improve your threat detection and response capabilities and stay one step ahead of potential attackers.

If you have any questions or comments about WmiEye, please feel free to reach out to the project maintainer or submit an issue on the GitHub repository. We welcome any feedback or suggestions for improving the program.

## License

This program is licensed under the MIT License.

## Acknowledgments

WmiEye was inspired by the [Sigma project](https://github.com/Neo23x0/sigma) and uses the [curl](https://curl.se/) and [cJSON](https://github.com/DaveGamble/cJSON) libraries. Thanks to the developers of these projects for making their work available.

## Contact

If you have any questions or comments about WmiEye, please feel free to reach out to the project maintainer at [Linkedin](https://www.linkedin.com/in/0xmaz).

