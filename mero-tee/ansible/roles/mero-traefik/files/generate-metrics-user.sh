#!/bin/bash

set -e

METRICS_USER="$1"
METRICS_PASSWORD="$2"

if [ -z "$METRICS_USER" ] || [ -z "$METRICS_PASSWORD" ]; then
    echo "Usage: $0 <username> <password>"
    echo "Example: $0 'metrics' 'my-secure-password'"
    exit 1
fi

# Create users file with htpasswd hashed credentials
htpasswd -nbB "$METRICS_USER" "$METRICS_PASSWORD" > "/etc/traefik/metrics-users"

echo "Metrics users file created at: /etc/traefik/metrics-users"
