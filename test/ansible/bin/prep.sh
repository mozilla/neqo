#! /usr/bin/bash
set -x

echo '-1' >/proc/sys/kernel/perf_event_paranoid

if [ -e /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
        echo "Intel P-state driver detected, disabling turbo boost"
        echo 1 >/sys/devices/system/cpu/intel_pstate/no_turbo
fi
cpupower frequency-info
cpupower frequency-set -g performance || true

echo 0 >/sys/devices/system/cpu/cpu6/online # sibling of 2
echo 0 >/sys/devices/system/cpu/cpu7/online # sibling of 3

cset set --cpu=0-1,4-5 --set=system --cpu_exclusive
cset set --cpu 2-3 --set=cpu23
cset set --cpu 2 --set=cpu2
cset set --cpu 3 --set=cpu3

cset proc --move --fromset=root --toset=system --threads --kthread --force

chown -R root:bench /cpusets/cpu23 /cpusets/cpu2 /cpusets/cpu3 /cpusets/system
chmod -R g+rwX /cpusets/cpu23 /cpusets/cpu2 /cpusets/cpu3 /cpusets/system
