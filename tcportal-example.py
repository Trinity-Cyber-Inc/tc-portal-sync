#!/usr/bin/env python

from getpass import getpass
import json
import os
import copy
import time
import argparse
import requests

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
    args = parser.parse_args()

    from_time = args.begin
    to_time = args.end
    customer_ids = args.customer_ids
    api_key = get_api_key(args)

    tc3path = os.path.expanduser(MARKER_FILE_DIR)
    print(f"Checking if directory {tc3path} exists to hold the after maker file.")
    if not os.path.exists(tc3path):
        print(f"Creating directory {tc3path} to hold the after marker file.")
        os.mkdir(tc3path)
    while True:
        got_events = False
        for event in get_events(
            api_key, from_time, to_time, customer_ids, args.flatten
        ):
            got_events = True
            print(json.dumps(event))
        if not got_events:
            print(f"Received 0 events, waiting and checking again.")
            time.sleep(30)
