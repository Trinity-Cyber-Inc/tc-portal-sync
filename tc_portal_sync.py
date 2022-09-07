#!/usr/bin/env python
import argparse
import copy
import json
import logging.config
import socket
import sys
import time
from datetime import datetime
from datetime import timezone
from pathlib import Path

import boto3
import botocore.exceptions
import certifi
import dateutil
import dateutil.parser
import requests

# For a custom CA; if no custom CA is used, comment out this line.
certifi.where = lambda: "/etc/pki/tls/cert.pem"

# Configure logging
hostname = socket.gethostname()
logger = logging.getLogger("trinity-events")
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s %(name)s %(levelname)s %(message)s ",
)


graphql_query = """
    query QUERY_NAME ($first: Int, $last: Int, $after: String, $filter: EventFilter) {
      events(first: $first, last: $last, after: $after, filter: $filter) {
        pageInfo {
          hasNextPage
          endCursor
        }
        edges {
          cursor
          node {
            id
            actionTime
            source
            destination
            sourcePort
            destinationPort
            transportProtocol
            direction
            trustInitiated
            formulaMatches {
                action {
                    response
                } 
                formula {
                  formulaId
                  title
                  background
                  tags {
                    category
                    value
                  }
                }
            }
            applicationProtocol
            applicationData {
              __typename
              ... on HttpRequestData {
                method
                path
                host
                userAgent
              }
              ... on HttpResponseData {
                statusCode
                statusString
                server
                contentType
              }
              ... on DnsData {
                host
              }
              ... on TlsData {
                sniHost
              }
            }
          }
        }
      }
    }
    """


class StreamOutput:
    def __init__(self, output_config):
        self.flatten = output_config["flatten"]
        self.mapping = output_config.get("field_mapping", {})
        format = output_config.get("format", "json")
        if format == "json":
            self.formatter = self.format_json
        elif format == "leef":
            self.flatten = True
            self.formatter = self.format_leef

    def output_event(self, event):
        if self.flatten:
            for flattened_event in flatten_event(event):
                content = self.formatter(flattened_event)
                print(content)
        else:
            content = self.formatter(event)
            print(content)

    def output_no_results(self):
        pass

    def format_json(self, event):
        mapped_event = apply_mapping(self.mapping, event)
        return json.dumps(mapped_event).encode("UTF-8")

    @staticmethod
    def format_leef(event):
        """Format an event as QRadar / LEEF"""

        syslog_header = f'<13>1 {event["actionTime"]} {hostname}'
        leef_header = f'LEEF:2.0|TrinityCyber|PTI|1|{event.pop("id")}|xa6|'
        fields = dict()

        fields["devTime"] = event.pop("actionTime")
        fields[
            "devTimeFormat"
        ] = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"  # (e.g. 2022-04-25T00:01:19.109+00:00)

        # LEEF-standard fields
        if "source" in event:
            fields["src"] = event.pop("source")
        if "destination" in event:
            fields["dst"] = event.pop("destination")
        if "sourcePort" in event:
            fields["srcPort"] = event.pop("sourcePort")
        if "destinationPort" in event:
            fields["dstPort"] = event.pop("destinationPort")
        if "transportProtocol" in event:
            fields["proto"] = event.pop("transportProtocol")

        # Formula-related metadata
        formula_metadata = event.pop("formula")
        fields["tcFormulaId"] = formula_metadata["formulaId"]
        fields["tcFormulaTitle"] = formula_metadata["title"]
        for key, value in formula_metadata["tags"].items():
            key = "tcFormula" + key.title().replace(" ", "")
            fields[key] = value

        # Application / protocol related data
        for app_fields in event.pop("applicationData"):
            for key, value in app_fields.items():
                if value is None:
                    continue
                if isinstance(value, str):
                    # Escape delimiter
                    value = value.replace("\xa6", "\\\xa6")
                fields[key] = value

        # Add any extra information from the query
        fields.update(event)

        fields_formatted = "\xa6".join(
            [f"{key}={value}" for key, value in fields.items()]
        )
        return f"{syslog_header} {leef_header}{fields_formatted}"


class BaseBucketEventOutput:
    def __init__(self, output_config):
        self.flatten = output_config["flatten"]
        self.key_base = output_config["key_base"]
        self.flatten = output_config["flatten"]
        self.mapping = output_config.get("field_mapping", {})
        assert (
            output_config.get("format", "json") == "json"
        ), "This output only accepts JSON format"

        if self.key_base:
            if self.key_base[0] == "/":
                self.key_base = self.key_base[1:]
            if not self.key_base[-1] == "/":
                self.key_Base = self.key_base + "/"

    def generate_key(self, event, index=0):
        """Returns the key / filename used to store the event"""
        event_time = dateutil.parser.parse(event["actionTime"])
        event_id_hash = event["id"].split("/")[-1]
        return f'{self.key_base}{event_time.strftime("%Y/%m/%d")}/{event_id_hash}_{index}.json'

    def output_event(self, event):
        if self.flatten:
            for index, flattened_event in enumerate(flatten_event(event)):
                key = self.generate_key(flattened_event, index)
                mapped_event = apply_mapping(self.mapping, flattened_event)
                content = json.dumps(mapped_event).encode("UTF-8")
                self.write_content_to_bucket(key, content)
        else:
            key = self.generate_key(event)
            content = json.dumps(event).encode("UTF-8")
            self.write_content_to_bucket(key, content)

    def output_no_results(self):
        now_time = datetime.now(tz=timezone.utc)
        fmt_time = now_time.isoformat(timespec="milliseconds")
        no_results = dict(
            time=fmt_time,
            status="no results",
            result=f"Trinity Cyber Portal check-in at {fmt_time} and did not detect any new events, "
            f"waiting until next scheduled check-in.",
        )
        key = f'{self.key_base}{now_time.strftime("%Y/%m/%d/no_data_%H%M%S.json")}'
        content = json.dumps(no_results).encode("UTF-8")
        self.write_content_to_bucket(key, content)

    def write_content_to_bucket(self, key, content):
        raise NotImplemented("Implemented in subclasses")


class DirectoryOutput(BaseBucketEventOutput):
    """Outputs to a local directory with one file per event"""

    def __init__(self, output_config):
        super().__init__(output_config)
        directory = Path(output_config["directory"])
        assert directory.is_dir(), f"{directory.absolute()} is not a directory"
        self.directory = directory

    def write_content_to_bucket(self, key, content):
        file_path = self.directory / key
        if not file_path.parent.exists():
            file_path.parent.mkdir(parents=True)
        file_path.write_bytes(content)


class S3BucketOutput(BaseBucketEventOutput):
    """Outputs to an S3 bucket with one file per event"""

    def __init__(self, output_config):
        super().__init__(output_config)
        self.client = boto3.client("s3", region_name=output_config["s3_region"])
        self.bucket = output_config["s3_bucket"]
        self.retry_interval = output_config["retry_delay_ms"] / 1000

    def write_content_to_bucket(self, key, content):
        uploaded = False
        while not uploaded:
            try:
                upload_start = time.perf_counter()
                self.client.put_object(Bucket=self.bucket, Key=key, Body=content)
                upload_duration = time.perf_counter() - upload_start
                logger.info(
                    f"Uploaded {key} in {upload_duration} seconds to s3://{self.bucket}"
                )
                uploaded = True
            except botocore.exceptions.ClientError as e:
                logger.error(
                    f"Failed to upload {key}. Waiting {self.retry_interval} ms and trying again. The exception was:\n{e}"
                )
                time.sleep(self.retry_interval / 1000)


def flatten_event(event):
    """
    Transforms an event into one or more flattened events.

    Flattening is sometimes needed to support SIEMs that can't store or query the nested structure of Trinity
    Cyber events.   The process takes an event that may contain more than one formula match and converts it into
    several events each containing a single formula match.   It also simplifies the tag structure of the events.
    """
    formula_matches = event.pop("formulaMatches", [])
    for match in formula_matches:
        event_copy = copy.deepcopy(event)
        del event_copy["applicationData"]
        for key, value in match["formula"].items():
            event_copy[key] = value
        event_copy["response"] = match["action"]["response"]
        event_copy["tags"] = {}
        for tag in match["formula"]["tags"]:
            category = tag["category"]
            value = tag["value"]
            if category in match["formula"]["tags"]:
                event_copy["tags"][category] += f"; {value}"
            else:
                event_copy["tags"][category] = value
        for app_data in event["applicationData"]:
            typename = app_data.pop("__typename")
            for key, value in app_data.items():
                event_copy[f"{typename}.{key}"] = value
        yield event_copy


def apply_mapping(mapping, event):
    result = dict()
    for key, value in event.items():
        if key in mapping:
            result[mapping[key]] = value
        else:
            stripped_key = key.split(".")[-1]
            result[stripped_key] = value
    return result


class TcPortalClient:
    """Client for interacting with the Trinity Cyber Customer Portal API"""

    def __init__(self, portal_config):
        api_key = portal_config["api_key"]
        self.session = requests.Session()
        self.session.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        self.api_url = portal_config["api_url"]
        self.customers = portal_config.get("customer_gids") or None
        self.query_name = portal_config["query_name"]
        self.marker_file = Path(portal_config["marker_file"]).expanduser()
        if not self.marker_file.parent.exists():
            logger.info(
                "Creating directory %s to hold the after marker file.",
                self.marker_file.parent,
            )
            self.marker_file.parent.mkdir(parents=True)

    def graphql(self, query, **variables):
        """Runs a GraphQL query against the Trinity Cyber Portal API"""
        query_formatted = query.replace("QUERY_NAME", self.query_name)
        submission_data = {"query": query_formatted, "variables": variables}
        result = self.session.post(self.api_url, json=submission_data)
        result.raise_for_status()
        result_json = result.json()
        return result_json

    def get_events(self, since=None, last=None):
        """Returns a generator that iterates over all events since the marker"""
        after_marker = None
        have_more_pages = True
        logger.debug("Getting events")
        while have_more_pages:
            logger.debug("Has more pages: %s", have_more_pages)
            if self.marker_file.exists():
                after_marker = self.marker_file.read_text()
            variables = dict(filter=dict())
            if self.customers:
                variables["filter"]["customers"] = self.customers
            if since:
                variables["first"] = 1000
                variables["filter"]["fromTime"] = since
            elif last:
                variables["last"] = last
            else:
                variables["first"] = 1000
                variables["after"] = after_marker

            result_json = self.graphql(graphql_query, **variables)
            end_cursor = result_json["data"]["events"]["pageInfo"]["endCursor"]
            if end_cursor is not None:
                for edge in result_json["data"]["events"]["edges"]:
                    yield edge["node"]
                    self.marker_file.write_text(edge["cursor"])
            have_more_pages = result_json["data"]["events"]["pageInfo"]["hasNextPage"]

    def get_customers(self) -> dict:
        """Return a list of customers and their IDs."""
        query = """
            query TcScriptClientListCustomers {
              customers(first: 1000) {
                edges {
                  node {
                    id
                    name
                  }
                }
              }
            }        
        """
        rv = self.graphql(query)
        return {
            edge["node"]["id"]: edge["node"]["name"]
            for edge in rv["data"]["customers"]["edges"]
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, help="Path to configuration file")
    parser.add_argument(
        "--since",
        help="Re-processes events since the specified time (in ISO-8601 format).",
    )
    parser.add_argument(
        "--last",
        type=int,
        help="Re-processes the last X events.",
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run once and exit after printing event",
    )
    parser.add_argument(
        "--list-customers",
        action="store_true",
        help="List customers.  This is intended for MSPs that are managing multiple customers under Trinity Cyber.",
    )

    args = parser.parse_args()

    config_path = args.config
    if config_path:
        # Instance not specified in systemd startup, so use default
        if config_path.match("/opt/trinity/tc-portal-sync/config-.json"):
            config_path = Path("/opt/trinity/tc-portal-sync/config.json")
    else:
        config_path = Path(__file__).resolve().parent / "config.json"
    if not config_path.exists():
        logger.error("Could not find configuration file: %s", args.config)
        sys.exit(1)
    with config_path.open() as config_fp:
        config = json.load(config_fp)

    client = TcPortalClient(config["trinity_cyber_portal"])

    # List customers and exit
    if args.list_customers:
        print("{0:40}{1}".format("Customer ID", "Customer Name"))
        print("{0:40}{1}".format("-----------", "-------------"))
        for customer_id, customer_name in client.get_customers().items():
            print("{0:40}{1}".format(customer_id, customer_name))
        sys.exit(0)

    # Configure one or more outputs for events
    outputs = []
    for output in config["outputs"]:
        if output["enabled"] is False:
            continue
        if output["type"] == "stream":
            outputs.append(StreamOutput(output))
        elif output["type"] == "directory":
            outputs.append(DirectoryOutput(output))
        elif output["type"] == "s3":
            outputs.append(S3BucketOutput(output))

    while True:
        got_events = False
        events_received = 0
        for event in client.get_events(since=args.since, last=args.last):
            events_received += 1
            for output in outputs:
                output.output_event(event)

        args.since = None
        if args.last or args.once:
            break

        if events_received == 0:
            for output in outputs:
                output.output_no_results()

        delay = config["trinity_cyber_portal"]["poll_interval_seconds"]
        logger.info(
            "Processed %d events. Waiting %d seconds and checking again.",
            events_received,
            delay,
        )
        time.sleep(delay)
