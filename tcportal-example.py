#!/usr/bin/env python
import socket
from getpass import getpass
import json
import os
import copy
import logging
import sys
import time
import argparse
import requests


hostname = socket.gethostname()
logger = logging.getLogger("tcportal-example")
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s %(name)s %(levelname)s %(message)s ",
)

FROM_TIME = None
TO_TIME = None
TRINITY_PORTAL_CLIENT_ID = None
TRINITY_PORTAL_API_URL = "https://portal.trinitycyber.com/graphql"
MARKER_FILE_DIR = "~/.tc3/"
MARKER_FILE = "tc-portal-end-cursor"
MARKER_PATH = os.path.expanduser(os.path.join(MARKER_FILE_DIR, MARKER_FILE))

graphql_query = """
query RecentEvents($after: String, $fromTime: DateTime, $toTime: DateTime) {
  events(first: 100, after: $after, filter:{fromTime: $fromTime, toTime: $toTime}) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        id
        actionTime
        source
        destination
        sourcePort
        destinationPort
        transportProtocol
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


def get_api_key(args):
    api_key = args.api_key
    if not api_key and "TC_API_KEY" in os.environ:
        api_key = os.environ["TC_API_KEY"]
    if not api_key:
        api_key = getpass("Please enter your Trinity Cyber customer portal API key: ")
    return api_key


def get_events(api_key, from_time, to_time, client_ids, flatten):
    """Returns a generator that iterates over all events since the marker"""
    https_session = requests.Session()
    https_session.headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    if client_ids:
        https_session.headers["X-Effective-Client-Ids"] = f"{client_ids}"
    after_marker = None
    have_more_pages = True
    while have_more_pages:
        if os.path.isfile(MARKER_PATH):
            with open(MARKER_PATH, "r") as marker_file:
                after_marker = marker_file.read()
        variables = {
            "after": after_marker,
        }
        if from_time is not None:
            variables["fromTime"] = from_time
        if to_time is not None:
            variables["toTime"] = to_time
        submission_data = {"query": graphql_query, "variables": variables}
        result = https_session.post(TRINITY_PORTAL_API_URL, json=submission_data)
        result.raise_for_status()
        result_json = result.json()
        end_cursor = result_json["data"]["events"]["pageInfo"]["endCursor"]
        if end_cursor is not None:
            for edge in result_json["data"]["events"]["edges"]:
                node = edge["node"]
                if flatten:
                    formula_matches = node.pop("formulaMatches")
                    for match in formula_matches:
                        node_copy = copy.deepcopy(node)
                        node_copy["formula"] = copy.deepcopy(match["formula"])
                        tags = node_copy["formula"].pop("tags")
                        node_copy["formula"]["tags"] = {}
                        for tag in tags:
                            category = tag["category"]
                            value = tag["value"]
                            if category in node_copy["formula"]["tags"]:
                                node_copy["formula"]["tags"][category] += f"; {value}"
                            else:
                                node_copy["formula"]["tags"][category] = value
                        yield node_copy
                else:
                    yield node
            with open(MARKER_PATH, "w+") as marker_file:
                marker_file.write(end_cursor)
        have_more_pages = result_json["data"]["events"]["pageInfo"]["hasNextPage"]


def format_event_json(event):
    """Format an event as JSON"""
    return json.dumps(event)


def format_event_leef(event):
    """Format an event as QRadar / LEEF"""

    syslog_header = f'<13>1 {event["actionTime"]} {hostname}'
    leef_header = f'LEEF:2.0|TrinityCyber|PTI|1|{event["id"]}|xa6|'
    fields = dict()

    fields["devTime"] = event["actionTime"]
    fields[
        "devTimeFormat"
    ] = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"  # (e.g. 2022-04-25T00:01:19.109+00:00)

    # LEEF-standard fields
    if "source" in event:
        fields["src"] = event["source"]
    if "destination" in event:
        fields["dst"] = event["destination"]
    if "sourcePort" in event:
        fields["srcPort"] = event["sourcePort"]
    if "destinationPort" in event:
        fields["dstPort"] = event["destinationPort"]
    if "transportProtocol" in event:
        fields["proto"] = event["transportProtocol"]

    # Formula-related metadata
    fields["tcFormulaId"] = event["formula"]["formulaId"]
    fields["tcFormulaTitle"] = event["formula"]["title"]
    for key, value in event["formula"]["tags"].items():
        key = "tcFormula" + key.title().replace(" ", "")
        fields[key] = value

    # Application / protocol related data
    for app_fields in event["applicationData"]:
        for key, value in app_fields.items():
            if value is None:
                continue
            if isinstance(value, str):
                # Escape delimiter
                value = value.replace("\xa6", "\\\xa6")
            fields[key] = value

    fields_formatted = "\xa6".join([f"{key}={value}" for key, value in fields.items()])
    return f"{syslog_header} {leef_header}{fields_formatted}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-b",
        "--begin",
        help="Query begin time in ISO 8601 format (1970-01-01T00:00:00Z)",
        default=None,
        required=False,
    )
    parser.add_argument(
        "-e",
        "--end",
        help="Query end time in ISO 8601 format (1970-01-01T00:00:00Z)",
        default=None,
        required=False,
    )
    parser.add_argument(
        "-c",
        "--customer-ids",
        help="The customer IDs to query for; a comma separated list, no spaces (1,2,3)",
        default=None,
        required=False,
    )
    parser.add_argument(
        "-k",
        "--api-key",
        help="NOT PREFERRED! Use with caution! Your Trinity Cyber customer portal API key. "
        + "If used from the CLI, this will leave your key in your shell history. "
        + "Prefer using the environment variable TC_API_KEY or entering the value whne prompted.",
        default=None,
        required=False,
    )
    parser.add_argument(
        "-f",
        "--flatten",
        help="Flatten events to a JSON object per formula hit with tags flattened to a semicolon (;) separated list.",
        default=False,
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "--format",
        help="Output format used to print events",
        default="json",
        choices=["json", "leef"],
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run once and exit after printing event",
    )

    args = parser.parse_args()

    from_time = args.begin
    to_time = args.end
    customer_ids = args.customer_ids
    api_key = get_api_key(args)
    format_func = format_event_json
    if args.format == "leef":
        args.flatten = True
        format_func = format_event_leef

    tc3path = os.path.expanduser(MARKER_FILE_DIR)
    logger.info(
        f"Checking if directory %s exists to hold the after maker file.", tc3path
    )
    if not os.path.exists(tc3path):
        logger.info("Creating directory %s to hold the after marker file.", tc3path)
        os.mkdir(tc3path)
    while True:
        got_events = False
        for event in get_events(
            api_key, from_time, to_time, customer_ids, args.flatten
        ):
            got_events = True
            print(format_func(event))
        if got_events is False:
            if args.once:
                break
            logger.info(f"Received 0 events, waiting and checking again.")
            time.sleep(30)
