#!/bin/bash
# usage: bash mn.sh 2      start the controller first (ctrl.sh); test 3 uses 6 hosts, the others 4
cd "$(dirname "$0")"
if ! ss -ltn | grep -q ":6653 "; then echo "Controller is NOT running. In another tab run first:  bash ctrl.sh $1"; exit 1; fi
N=4
if [ "$1" = "3" ]; then N=6; fi
sudo mn --topo single,$N --controller remote --switch ovsk,protocols=OpenFlow13 --mac
