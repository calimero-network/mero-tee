#!/bin/bash
# fetch_secret.sh
# Usage: ./fetch_secret.sh <provider> <secret_name>
#
# Providers: aws, gcp, provided
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

  provided)
    # The token was handed to this node by mdma over the attested fleet channel
    # and written to disk by the sidecar. Nothing to fetch: it is already here,
    # and there is no cloud identity on these instances to fetch it with.
    #
    # `$2` is an absolute path rather than a secret name. Read it as-is; an
    # unreadable or empty file is a hard failure, because configuring vector
    # with an empty Authorization header would send every log line unauthorized
    # and look like a sink problem rather than a credential one.
    if [[ ! -s "$2" ]]; then
      echo "provided token file $2 is missing or empty" >&2
      exit 1
    fi
    cat "$2"
    ;;
  gcp)
    # Use gcloud to fetch secret
    gcloud secrets versions access latest \
      --secret="$SECRET_NAME" \
      --format='get(payload.data)' | base64 -d
    ;;

  *)
    echo "Unknown provider: $PROVIDER" >&2
    echo "Supported providers: aws, gcp, provided" >&2
    exit 1
    ;;
esac
