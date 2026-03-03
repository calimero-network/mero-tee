#!/bin/bash

# setup_vector_config.sh
# Usage: sudo ./setup_vector_config.sh <victorialogs_endpoint_url> <instance_type> <instance_name> <systemd_service_name>
#
# Example:
# sudo ./setup_vector_config.sh http://victoria-logs-int.apps.dev.p2p.aws.calimero.network:80/insert/elasticsearch ec2 my-ec2-node-1 merod.service

set -euo pipefail

if [ $# -ne 4 ]; then
    echo "Usage: $0 <victorialogs_endpoint_url> <instance_type> <instance_name> <systemd_service_name>"
    exit 1
fi

VICTORIA_LOGS_ENDPOINT="$1"
INSTANCE_TYPE="$2"
INSTANCE_NAME="$3"
SYSTEMD_SERVICE_NAME="$4"
VECTOR_CONFIG_PATH="/etc/vector/vector.yaml"

echo "Creating Vector configuration file at $VECTOR_CONFIG_PATH"

sudo mkdir -p /etc/vector

sudo tee "$VECTOR_CONFIG_PATH" > /dev/null <<EOF
sources:
  app_journal:
    type: journald
    include_units: ["${SYSTEMD_SERVICE_NAME}"]
    data_dir: "/etc/vector/data"

transforms:
  add_labels:
    type: remap
    inputs: [app_journal]
    source: |
      .unit = ._SYSTEMD_UNIT
      .hostname = .host
      .instance_name = "${INSTANCE_NAME}"
      .instance_type = "${INSTANCE_TYPE}"

sinks:
  victoria_logs:
    type: elasticsearch
    inputs:
      - add_labels
    api_version: v8
    compression: gzip
    endpoints:
      - "${VICTORIA_LOGS_ENDPOINT}"
    mode: bulk
    healthcheck:
      enabled: false
    request:
      headers:
        AccountID: "0"
        ProjectID: "0"
        VL-Msg-Field: message
        VL-Stream-Fields: stream,hostname,unit,instance_name,instance_type
        VL-Time-Field: timestamp
EOF

echo "Vector configuration successfully written."
echo "Please restart the Vector service to apply changes:"
echo "  sudo systemctl restart vector"
