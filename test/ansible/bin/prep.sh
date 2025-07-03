#! /usr/bin/bash
set -x
#set -x -Eeuo pipefail
#shopt -s globstar

echo '-1' >/proc/sys/kernel/perf_event_paranoid

echo 1 >/sys/devices/system/cpu/intel_pstate/no_turbo
cpupower frequency-set -g performance

echo 0 >/sys/devices/system/cpu/cpu6/online # sibling of 2
echo 0 >/sys/devices/system/cpu/cpu7/online # sibling of 3

cset set --cpu=0-1,4-5 --set=system --cpu_exclusive
cset set --cpu 2-3 --set=cpu23
cset set --cpu 2 --set=cpu2
cset set --cpu 3 --set=cpu3

cset proc --move --fromset=root --toset=system --threads --kthread --force

chown -R root:bench /cpusets/cpu23 /cpusets/cpu2 /cpusets/cpu3 /cpusets/system
chmod -R g+rwX /cpusets/cpu23 /cpusets/cpu2 /cpusets/cpu3 /cpusets/system
