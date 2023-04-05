# WmiEye

WmiEye is a C program that monitors the Windows Management Instrumentation (WMI) event logs for any events that match Sigma rules and sends alerts to Elasticsearch. The program is designed to run in the background and can be used for threat detection and response.

The program reads Sigma rules from JSON files in the `sigmarules` directory and compares them with WMI event log entries. If there is a match between an event log entry and a Sigma rule, the program sends an alert to Elasticsearch with the event and rule information. The program also uses bookmarks to keep track of the last event processed and resumes monitoring after a restart.

## Features

The main features of the WmiEye program are:

- Reads Sigma rules from JSON files in the `sigmarules` directory.
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

1. Clone the repository to your local machine using the following command: `git clone https://github.com/yourusername/WmiEye.git`
2. Open the solution file `WmiEye.sln` in Visual Studio.
3. Build the solution.
4. Install the libcurl and libcjson libraries. You can download the libraries from the following links:
- [libcurl](https://curl.se/download.html)
- [libcjson](https://github.com/DaveGamble/cJSON/releases)
5. Copy the `libcurl.dll` and `libcjson.dll` files to the same directory as the executable file.
6. Run the program with administrator privileges.

## Usage

To use the WmiEye program, follow these steps:

1. Create a new JSON file in the `sigmarules` directory with the following format:
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
Replace the fields with appropriate values for your rule.

2. Edit the config.h file with the appropriate settings for your environment, such as the name of the WMI event log to monitor and the URL of the Elasticsearch server to send alerts to.

Run the program with administrator privileges.
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
To add this rule to the program, save it as a file named rule1.json in the sigmarules directory.

## Configuration
The WmiEye program can be configured using the config.h file. Here are the available options:

LOG_NAME: The name of the WMI event log to monitor. The default value is "Microsoft-Windows-WMI-Activity/Operational".
ELASTICSEARCH_URL: The URL of the Elasticsearch server to send alerts to. The default value is "http://localhost:9200".
BOOKMARK_FILE: The path of the bookmark file to use for event monitoring. The default value is "bookmarks.dat". Set to NULL to disable bookmarks.

## Limitations

The WmiEye program has a few limitations that you should be aware of:

The program only monitors the WMI event logs for events that match Sigma rules. It does not perform any other types of monitoring, such as network traffic or file system activity.
The program relies on Sigma rules to detect threats. If a threat is not covered by a Sigma rule, the program will not detect it.
The program may generate a high volume of alerts if there are many events that match the Sigma rules. You should configure Elasticsearch to handle this volume of data.

## License

This program is licensed under the MIT License.

## Monitoring Multiple WMI Event Logs

By default, WmiEye monitors the Microsoft-Windows-WMI-Activity/Operational event log for WMI events. If you want to monitor other event logs as well, you can modify the LOG_NAME parameter in the config.h file. For example, if you want to monitor both the Security and System event logs, you can set the LOG_NAME parameter to "Security,System".

## Using Sigma Rules from a Directory

In addition to using Sigma rules from individual JSON files, you can also use Sigma rules from a directory. To do this, simply save your Sigma rules in the sigmarules directory with the .json extension. WmiEye will automatically read all JSON files in the directory and use them for monitoring.

## Disabling Bookmarks

If you don't want WmiEye to use bookmarks to keep track of the last event processed, you can set the BOOKMARK_FILE parameter in the config.h file to NULL. This will disable bookmarks and WmiEye will start monitoring events from the beginning of the event log each time it is run.

## Using a Different Elasticsearch Server

If you want to send alerts to an Elasticsearch server other than the default `http://localhost:9200` you can modify the `ELASTICSEARCH_URL` parameter in the `config.h` file. For example, if your Elasticsearch server is running on a different port, you can set the `ELASTICSEARCH_URL` parameter to `http://localhost:9201`.

## Conclusion

WmiEye is a powerful tool for detecting threats in the WMI event logs using Sigma rules. It is easy to configure and use, and can be integrated with Elasticsearch for alerting and analysis. By using WmiEye in your environment, you can improve your threat detection and response capabilities and stay one step ahead of potential attackers.

If you have any questions or comments about WmiEye, please feel free to reach out to the project maintainer or submit an issue on the GitHub repository. We welcome any feedback or suggestions for improving the program.
