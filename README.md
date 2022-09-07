### Overview
This application serves as a reference implementation for using the [GraphQL](https://graphql.org/learn/) API of the
[Trinity Cyber Customer Portal](https://portal.trinitycyber.com) to pull events and save them to a variety of sources,
including the local filesystem and S3.

The API itself follows [Relay GraphQL Cursor Connections Specification](https://relay.dev/graphql/connections.htm) for
pagination. There is an [embedded GraphQL Playground](https://portal.trinitycyber.com/graphql-playground) embedded in
our customer portal to try out some of these queries.

This API works great for both ad-hoc queries as well as continual synchronization to another database or tool. This
script is an example of how to query the API, save off the "end cursor" for each page of data processed, and emit
events to be processed or submitted to another system.

### Requirements
This is a Python 3 script; it was developed on CentOS 7 with Python 3.6 but should be broadly applicable to most Python
3  variants on most UNIX based operating systems.  Library dependencies are listed in requirements.txt and can be
installed using "pip install -r requirements.txt"

### Running as a Service
If installing as a service using the RPM, the script and config files will be placed in the 
/opt/trinity/tc-portal-sync/ directory.  Make sure any configuration files needed by the service
are accessible to the "tc-portal-sync" user.

To start the service, as root:
  * Edit the "/opt/trinity/tc-portal-sync/config-default.json" configuration file (see below for detail )
  * Run "systemctl start tc-portal-sync"

It is possible to run multiple instance of the service, each with its own configuration.  To do so:
  * Create a "/opt/trinity/tc-portal-sync/config-<instance_name>.json" file
  * Run "systemctl start tc-portal-sync@<instance_name>"

### Configuration
The configuration file for this application is "config-default.json" and it exists in the top-level project directory,
or in /opt/trinity/tc-portal-sync if installing via the RPM.

The "trinity_cyber_portal" section of the configuration file contains application-level settings:

| Field                 | Description                                                                                                                        |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------------|
| api_url               | The URL for the Trinity Cyber Portal GraphQL endpoint.  Keep the default unless accessing a custom portal instance.                |
| api_key               | API key.  This can be generated from your user profile menu (top right) on https://portal.trinitycyber.com                         |
| marker_file           | The file used to keep track of current synchronization state.                                                                      |
| customer_gids         | (For MSP users) Specifies which customers' events to download.  The values can be found by running "tc_portal_sync.py --customers" |
| poll_interval_seconds | How long to wait (in seconds) between API calls when no additional events are available.                                           |
| query_name            | Update with a descriptive query name that can be used for support purposes.  Example: MyCompanyMyApplication                       |

The "outputs" section consists of a list of event output destinations.  Each entry in the
list is a JSON object with the following fields:

| Field         | Description                                               |
|---------------|-----------------------------------------------------------|
| type          | Output type (see below)                                   |
| enabled       | Specifies if the output is enabled or not                 |
| field_mapping | An override mapping of field names to new field names\*   |
| flatten       | Flattens events to remove nested JSON structures          |
| format        | "json" for JSON output, or "leef" for QRadar LEEF format  |

*Note - the field_mapping option only applies when flattened is true. Re-mapping structured
data is not currently supported.

#### Output Type: stdout
This "stdout" output type writes events to standard output and is helpful if running the script
directly. There are no additional parameters that apply to this output type.

#### Output Type: directory
The "directory" output type writes a file per-event to a local directory.  These additional
fields apply:

| Field     | Description                                                              |
|-----------|--------------------------------------------------------------------------|
| directory | The directory where event files will be written.                         |
| key_base  | Specifies a prefix to be added to files                                  |

#### Output Type: s3
The "s3" output type write a file per-event to an S3 bucket.  This will use the credentials
found in the ~/.aws/credentials file.  You can use the AWS command-line tool to initialize
this file.

These additional fields apply:

| Field          | Description                                                               |
|----------------|---------------------------------------------------------------------------|
| s3_bucket      | The name of the S3 bucket to write to.                                    |
| s3_region      | The region of the S3 bucket to write to                                   |
| key_base       | Specifies a prefix to be added to files                                   |
| retry_delay_ms | How quickly to retry uploading to S3                                      |


### Script Parameters

| Parameter   | Description                                                                                                                                    |
|-------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| --config    | Specifies an alternate configuration file                                                                                                      |
| --since     | Re-processes the event since the specified time (in ISO-8601 format) rather than starting from the marker (or scratch if no marker is present) |
| --last      | Re-processes last X events rather than starting from the marker (or scratch if no marker is present)                                           |
| --once      | Processes all the events and exits without periodically re-polling the API.
| --customers | (For MSP users) prints a list of available customers

### End cursor file
Every time you run this script, it updates the same `~/.tc3/tc-portal-end-cursor` file with the
"last page of events" marker. This is set up the script can be run with a set of parameters on an
interval: come back in 30 seconds, 5 minutes, a day, or a month later and run the SAME query again
to get all new events since the last time the script was run. This is the typical "get new events
to feed into a SIEM" use case. By default, the script sleeps for 300 seconds and re-queries until killed.

If you change query parameters between runs, update the fields being requested, or make other
modifications you will need to erase the `~/.tc3/tc-portal-end-cursor` file and start from scratch.

### Time ranges and cursors
If you request all events between *begin* and *end* and consume all of the events, no new events will show up on future queries unless *end* is in the future relative to when the query was last run. Re-running with *begin* set to an earlier date will NOT pull in the "differential update" for "before the last begin date". While that kind of reverse time query IS possible by switching up the script to use "before" instead of "after" and reverse iterating, this script was meant to be a simple example of typical "query all history and keep filling into the future" usage.
