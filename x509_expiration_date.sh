#!/usr/bin/env bash

if ! test -d pem_files; then
  mkdir pem_files
fi

while read hostname; do
  hostandport="$hostname:443"
  filename="pem_files/$hostname.pem"
  echo -n | openssl s_client -showcerts -servername $hostname -connect $hostandport > $filename  2>/dev/null
  result=`openssl x509 -in $filename -inform pem -noout -enddate`
  echo "$result $hostname"
done <hostlist.txt