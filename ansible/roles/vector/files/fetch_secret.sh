#!/bin/bash
# fetch_secret.sh
# Usage: ./fetch_secret.sh <provider> <secret_name>
#
# Providers: aws, gcp
# Example: ./fetch_secret.sh aws /merotee-instance-1/vmagent-token

set -euo pipefail

PROVIDER="$1"
SECRET_NAME="$2"

case "$PROVIDER" in
  aws)
    # Use AWS CLI to fetch secret
    aws secretsmanager get-secret-value \
      --secret-id "$SECRET_NAME" \
      --query SecretString \
      --output text
    ;;

  gcp)
    # Use gcloud to fetch secret
    gcloud secrets versions access latest \
      --secret="$SECRET_NAME" \
      --format='get(payload.data)' | base64 -d
    ;;

  *)
    echo "Unknown provider: $PROVIDER" >&2
    echo "Supported providers: aws, gcp" >&2
    exit 1
    ;;
esac
