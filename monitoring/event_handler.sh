#!/bin/sh

output_file="/var/log/openport.txt"

check_open_port() {
  echo "$event" >> "$output_file"
}

dispatch_event() {
  event="$1"
  
  # Extract the "tags" field and check for "open_port"
  tags=$(echo "$event" | jq -r '.tags')

  if [[ "$tags" == *"open_port"* ]]; then
    check_open_port "$event"
  fi
}

# Read events from stdin (passed by Falco)
while IFS= read -r line; do
  dispatch_event "$line"
done
