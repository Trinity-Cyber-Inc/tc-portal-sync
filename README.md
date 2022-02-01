### Requirements
This is a Python 3 script; it was developd on CentOS 7 with Python 3.6 but should be broadly applicable to most Python 3 variants on most \*NIX based operating systems. The only additional library requried is `requests`.

### Overview
The [Trinity Cyber Customer Portal](https://portal.trinitycyber.com) has a [GraphQL](https://graphql.org/learn/) API which uses the [Relay GraphQL Cursor Connections Specification](https://relay.dev/graphql/connections.htm) for pagination. There is an [embedded GraphQL Playground](https://portal.trinitycyber.com/graphql-playground) embedded in our customer portal to try out some of these queries.

This API works great for both ad-hoc queries as well as continual synchronization to another database or tool. This script is an example of how to query the API, save off the "end cursor" for each page of data processed, and emit events to be processed or submitted to another system. The general flow is:

### End cursor file
Every time you run this script, it updates the same `~/.tc3/tc-portal-end-cursor` file with the "last page of events" marker. This is set up the script can be run with a set of parameters on an interval: come back in 30 seconds, 5 minutes, a day, or a month later and run the SAME query again to get all new events since the last time the script was run. This is the typical "get new events to feed into a SIEM/SEIM" use case. By default, the script sleeps for 30s and re-queries until killed.

If you change query parameters between runs, update the fields being requested, or make other modifications you will need to erase the `~/.tc3/tc-portal-end-cursor` file and start from scratch.

### Time ranges and cursors
If you request all events between *begin* and *end* and consume all of the events, no new events will show up on future queries unless *end* is in the future relative to when the query was last run. Re-running with *begin* set to an earlier date will NOT pull in the "differential update" for "before the last begin date". While that kind of reverse time query IS possible by switching up the script to use "before" instead of "after" and reverse iterating, this script was meant to be a simple example of typical "query all history and keep filling into the future" usage.
