#! /usr/bin/bash
set -x
#set -x -Eeuo pipefail
#shopt -s globstar

cset set --destroy cpu2 --force
cset set --destroy cpu3 --force
cset set --destroy cpu23 --force
cset set --destroy system --force

echo 1 >/sys/devices/system/cpu/cpu6/online # sibling of 2
echo 1 >/sys/devices/system/cpu/cpu7/online # sibling of 3

echo 0 >/sys/devices/system/cpu/intel_pstate/no_turbo
cpupower frequency-set -g powersave
