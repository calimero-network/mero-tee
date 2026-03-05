#!/bin/bash
# configure_vmagent.sh
# Configure vmagent with pre-created scrape config, bearer token, and systemd service
#
# Usage: ./configure_vmagent.sh <config_file_path> <remote_write_url> <auth_enabled> <secret_provider> <secret_name>
#
# Parameters:
#   config_file_path   - Path to scrape config YAML file (e.g., /etc/vmagent/scrape_config.yml)
#   remote_write_url   - VictoriaMetrics remote write endpoint
#   auth_enabled       - "true" or "false"
#   secret_provider    - "aws" or "gcp" (only used if auth_enabled=true)
#   secret_name        - Secret name/path (only used if auth_enabled=true)
#
# Example:
# ./configure_vmagent.sh \
#   /etc/vmagent/scrape_config.yml \
#   "https://victoria-lb.apps.dev.p2p.aws.calimero.network/api/v1/write" \
#   true \
#   gcp \
#   victoria-lb-metrics-bearer-token

set -euo pipefail

if [ $# -ne 5 ]; then
    echo "Usage: $0 <config_file_path> <remote_write_url> <auth_enabled> <secret_provider> <secret_name>"
    exit 1
fi

CONFIG_FILE="$1"
REMOTE_WRITE_URL="$2"
AUTH_ENABLED="$3"
SECRET_PROVIDER="$4"
SECRET_NAME="$5"

echo "=== Configuring vmagent ==="
echo "Config file: $CONFIG_FILE"
echo "Remote write URL: $REMOTE_WRITE_URL"
echo "Authentication: $AUTH_ENABLED"

# 1. Validate config file exists
echo ""
echo "Step 1: Validating configuration file..."
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file $CONFIG_FILE does not exist"
    exit 1
fi
echo "Configuration file validated: $CONFIG_FILE"

# 2. Fetch bearer token if auth enabled
BEARER_TOKEN_FLAG=""
if [ "$AUTH_ENABLED" = "true" ]; then
    echo ""
    echo "Step 2: Fetching bearer token from $SECRET_PROVIDER..."
    /etc/vmagent/fetch_secret.sh "$SECRET_PROVIDER" "$SECRET_NAME" > /etc/vmagent/bearer_token
    chmod 600 /etc/vmagent/bearer_token
    BEARER_TOKEN_FLAG="-remoteWrite.bearerTokenFile=/etc/vmagent/bearer_token"
    echo "Bearer token fetched and saved"
else
    echo ""
    echo "Step 2: Skipping bearer token (auth disabled)"
fi

# 3. Create systemd service file
echo ""
echo "Step 3: Creating systemd service..."
cat > /etc/systemd/system/vmagent.service <<EOFSERVICE
[Unit]
Description=vmagent - VictoriaMetrics Agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vmagent \\
  -promscrape.config=$CONFIG_FILE \\
  -remoteWrite.url=$REMOTE_WRITE_URL \\
  -httpListenAddr=:8429 $BEARER_TOKEN_FLAG
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOFSERVICE

echo "Systemd service created at /etc/systemd/system/vmagent.service"

# 4. Reload systemd and enable service
echo ""
echo "Step 4: Enabling and starting vmagent service..."
systemctl daemon-reload
systemctl enable vmagent
systemctl restart vmagent

echo ""
echo "=== vmagent configuration complete ==="
echo ""
systemctl status vmagent --no-pager
