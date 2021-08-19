#!/bin/bash
input="./config/config_files/domain_test.txt"
while IFS= read -r line
do
  report_name=$(echo "$line" |  tr . _)
  dnstwist --nameserver 8.8.8.8 -f json -r --mxcheck  "$line" > "./reports/${report_name}.json"

done < "$input"