#!/bin/bash
# configure_vector.sh
# Configure Vector with partial config, sink configuration, and optional bearer token authentication
#
# Usage: ./configure_vector.sh <partial_config_path> <victoria_logs_url> <auth_enabled> <secret_provider> <secret_name>
#
# Parameters:
#   partial_config_path   - Path to partial vector config with sources/transforms (e.g., /etc/vector/vector_partial.yaml)
#   victoria_logs_url     - Victoria Logs endpoint URL
#   auth_enabled          - "true" or "false"
#   secret_provider       - "aws" or "gcp" (only used if auth_enabled=true)
#   secret_name           - Secret name/path (only used if auth_enabled=true)
#
# Example:
# ./configure_vector.sh \
#   "/etc/vector/vector_partial.yaml" \
#   "https://victoria-lb.apps.dev.p2p.aws.calimero.network/insert/elasticsearch" \
#   true \
#   gcp \
#   victoria-lb-logs-bearer-token

set -euo pipefail

if [ $# -ne 5 ]; then
    echo "Usage: $0 <partial_config_path> <victoria_logs_url> <auth_enabled> <secret_provider> <secret_name>"
    exit 1
fi

PARTIAL_CONFIG_PATH="$1"
VICTORIA_LOGS_URL="$2"
AUTH_ENABLED="$3"
SECRET_PROVIDER="$4"
SECRET_NAME="$5"

VECTOR_CONFIG_PATH="/etc/vector/vector.yaml"

echo "=== Configuring Vector ==="
echo "Partial config: $PARTIAL_CONFIG_PATH"
echo "Victoria Logs URL: $VICTORIA_LOGS_URL"
echo "Authentication: $AUTH_ENABLED"

# 1. Validate partial config exists
echo ""
echo "Step 1: Validating partial configuration file..."
if [ ! -f "$PARTIAL_CONFIG_PATH" ]; then
    echo "Error: Partial config file $PARTIAL_CONFIG_PATH does not exist"
    exit 1
fi
echo "Partial configuration file validated: $PARTIAL_CONFIG_PATH"

# 2. Fetch bearer token if auth enabled
AUTH_HEADER_LINE=""
if [ "$AUTH_ENABLED" = "true" ]; then
    echo ""
    echo "Step 2: Fetching bearer token from $SECRET_PROVIDER..."
    /etc/vector/fetch_secret.sh "$SECRET_PROVIDER" "$SECRET_NAME" > /etc/vector/bearer_token
    chmod 600 /etc/vector/bearer_token

    BEARER_TOKEN=$(cat /etc/vector/bearer_token)
    AUTH_HEADER_LINE="        Authorization: \"Bearer ${BEARER_TOKEN}\""
    echo "Bearer token fetched and saved"
else
    echo ""
    echo "Step 2: Skipping bearer token (auth disabled)"
fi

# 3. Create final Vector configuration
echo ""
echo "Step 3: Creating final Vector configuration..."

# Read partial config content
PARTIAL_CONFIG=$(cat "$PARTIAL_CONFIG_PATH")

# Create final config with partial content + sink section
cat > "$VECTOR_CONFIG_PATH" <<EOFVECTOR
${PARTIAL_CONFIG}

sinks:
  victoria_logs:
    type: elasticsearch
    inputs:
      - add_labels
    api_version: v8
    compression: gzip
    endpoints:
      - "${VICTORIA_LOGS_URL}"
    mode: bulk
    healthcheck:
      enabled: false
    request:
      headers:
${AUTH_HEADER_LINE}
        AccountID: "0"
        ProjectID: "0"
        VL-Msg-Field: message
        VL-Stream-Fields: stream,hostname,unit,instance_name,instance_type
        VL-Time-Field: timestamp
EOFVECTOR

echo "Final Vector configuration created at $VECTOR_CONFIG_PATH"

# 4. Enable and restart vector service
echo ""
echo "Step 4: Enabling and restarting vector service..."
systemctl enable vector
systemctl restart vector

echo ""
echo "=== Vector configuration complete ==="
echo ""
systemctl status vector --no-pager
