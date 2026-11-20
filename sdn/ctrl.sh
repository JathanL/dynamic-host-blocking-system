#!/bin/bash
# usage: bash ctrl.sh 2     starts the Ryu controller and logs to tc2.log
cd "$(dirname "$0")"
sudo mn -c > /dev/null 2>&1   # mn -c also kills ryu-manager, so clean up BEFORE starting it
source ~/ryuenv/bin/activate
rm -f tc$1.log
ryu-manager controller_simple.py --log-file tc$1.log
