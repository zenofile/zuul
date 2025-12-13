#!/usr/bin/env bash 

N=${1:-15000000}

paste -d/ \
  <(hexdump -v -e '1/1 "%u." 1/1 "%u." 1/1 "%u." 1/1 "%u\n"' -n $((N*4)) /dev/urandom) \
  <(shuf -i 0-32 -n "$N" -r) > test_data_v4.txt
