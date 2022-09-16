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
3  variants on most UNIX based operating systems. Library dependencies are listed in requirements.txt and can be
installed using "pip install -r requirements.txt"

### Running as a Service
If installing as a service using the RPM, the script and config files will be placed in the 
/opt/trinity/tc-portal-sync/ directory. Make sure any configuration files needed by the service
are accessible to the "tc-portal-sync" user.

To start the service, as root:
  * Edit the "/opt/trinity/tc-portal-sync/config-default.json" configuration file (see below for detail )
  * Run "systemctl start tc-portal-sync"

It is possible to run multiple instance of the service, each with its own configuration. To do so:
  * Create a "/opt/trinity/tc-portal-sync/config-<instance_name>.json" file
  * Create a "/opt/trinity/tc-portal-sync/enviroment-<instance_name>" file
  * Run "systemctl start tc-portal-sync@<instance_name>"

When running as a service, the `environment-<instance_name>` file can store AWS credentials, proxy settings,
and CA chain paths for SSL verification with custom CA chains (e.g. for SSL decyption at a firewall). It will
be loaded when the process starts. Note placing credentials in the environment is not always considered best practice
and the use of the ~/.aws/ directory for S3 settings may be perferred.

### Configuration
The configuration file for this application is "config-default.json" and it exists in the top-level project directory,
or in /opt/trinity/tc-portal-sync if installing via the RPM.

The "trinity_cyber_portal" section of the configuration file contains application-level settings:

| Field                 | Description                                                                                                                        |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------------|
| api_url               | The URL for the Trinity Cyber Portal GraphQL endpoint. Keep the default unless accessing a custom portal instance.                 |
| api_key               | API key. This can be generated from your user profile menu (top right) on https://portal.trinitycyber.com                          |
| marker_file           | The file used to keep track of current synchronization state.                                                                      |
| customer_gids         | (For MSP users) Specifies which customers' events to download. The values can be found by running "tc_portal_sync.py --customers"  |
| poll_interval_seconds | How long to wait (in seconds) between API calls when no additional events are available.                                           |
| query_name            | Update with a descriptive query name that can be used for support purposes. Example: MyCompanyMyApplication                        |

The "outputs" section consists of a list of event output destinations. Each entry in the
list is a JSON object with the following fields:

| Field         | Description                                                                |
|---------------|----------------------------------------------------------------------------|
| type          | Output type (see below)                                                    |
| enabled       | Specifies if the output is enabled or not                                  |
| field_mapping | An override mapping of field names to new field names\*                    |
| flatten       | Flattens events to remove nested JSON structures                           |
| format        | "json" for JSON output, or "leef" for QRadar LEEF format                   |
| heartbeat     | If true, writes a heartbeat event on periodic runs if there is no new data |

*Note - the field_mapping option only applies when flattened is true. Re-mapping structured
data is not currently supported.

#### Output Type: stdout
This "stdout" output type writes events to standard output and is helpful if running the script
directly. There are no additional parameters that apply to this output type.

#### Output Type: directory
The "directory" output type writes a file per-event to a local directory. Output is written to:
/{directory}/{key_base}/{year}/{month}/{day}/{key_file_prefix-}{unqiue_event_id-event_index}.{format}
The values for {year, month, day} are taken from the event timestamp, not the current time.
These additional fields apply:

| Field           | Description                                                              |
|-----------------|--------------------------------------------------------------------------|
| directory       | The directory where event files will be written.                         |
| key_base        | Specifies a prefix to be added before the date path                      |
| key_file_prefix | Specifies a prefix to be added before event ID based file name           |

#### Output Type: s3
The "s3" output type write a file per-event to an S3 bucket. This will use the credentials
searched using the standard boto3 process including checking  in the ~/.aws/credentials file
and the AWS environment variables. When running as a service, an `environment-<instance>` file
can be created along with each `config-<instance>.json` file to store credentials, proxy settings,
and CA chain paths for SSL verification with custom CA chains (e.g. for SSL decyption at a firewall).
Output is written to S3 as:
s3://{s3_region}/{s3_bucket}/{key_base}/{year}/{month}/{day}/{key_file_prefix-}{unqiue_event_id-event_index}.{format}
The values for {year, month, day} are taken from the event timestamp, not the current time.

These additional fields apply:

| Field          | Description                                                               |
|-----------------|---------------------------------------------------------------------------|
| s3_bucket       | The name of the S3 bucket to write to.                                    |
| s3_region       | The region of the S3 bucket to write to                                   |
| key_base        | Specifies a prefix to be added to files                                   |
| key_file_prefix | Specifies a prefix to be added before event ID based file name            |
| retry_delay_ms  | How quickly to retry uploading to S3                                      |


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

## Bash Script
There's a wrapper bash script that installs as part of the RPM which wraps the Python runtime environment,
an instance environment file, and a config file. The syntax is:
`/opt/trinity/tc-portal-sync/run-portal-sync.sh <instance name> --args --to --the --python --script go here`
The first argument is the instance name: default, demo, etc. as a bare parameter. The remaining arguments
are forwarded to the python script directly. The instance name is converted to a config file and passed
as `--config /opt/trinity/tc-portal-sync/config-${instance}.json` to the python. An example invocation is:
`./run-portal-sync.sh default --last 10`
which would run the script with the default configuration pulling the last 10 events.
