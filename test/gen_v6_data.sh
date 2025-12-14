#!/usr/bin/env bash

N=${1:-5000000}

paste -d/ \
  <(hexdump -v -e '7/2 "%04x:" 1/2 "%04x\n"' -n $((N*16)) /dev/urandom) \
  <(shuf -i 0-128 -n "$N" -r) > test_data_v6.txt