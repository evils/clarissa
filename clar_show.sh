#!/usr/bin/env bash

(cat macs.csv ; echo "---"; cat /tmp/clarissa_list) | \
awk -F, 'BEGIN { mode="collect" } /---/ { mode = "xref" } \
(mode == "collect") { reg[$1] = $2 } (mode == "xref") { print $1, reg[$1] }' \
| tr -d '"[]-' | awk 'NF == 1 {print $1}; NF > 1 {print $2" "$3}' \
| sort | uniq
