#!/bin/sh
# fetch.sh <label>: copy /tmp/measure-<label> from the router to /tmp/u60-perf/<label>
L=$1; D=${POWER_OUT:-/tmp/u60-perf}/$L; rm -rf $D; mkdir -p $D
ssh -o BatchMode=yes -p 2222 root@192.168.0.1 "cd /tmp/measure-$L && tar cf - ." | tar xf - -C $D
python3 "$(dirname "$0")/analyze.py" $D
