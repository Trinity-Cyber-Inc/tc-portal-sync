#!/bin/bash
instance=$1
if [[ -z $instance ]]; then
    instance=default
fi

cd /opt/trinity/tc-portal-sync
source /opt/trinity/tc-portal-sync/runtime/bin/activate
source /opt/trinity/tc-portal-sync/environment-$instance
python /opt/trinity/tc-portal-sync/tc_portal_sync.py --config /opt/trinity/tc-portal-sync/config-${instance}.json ${@:2}
