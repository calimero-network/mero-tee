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
    # The token is already on this machine: either stamped as instance metadata
    # at creation and written out by calimero-init, or delivered later over the
    # attested fleet channel by the sidecar. Nothing to fetch, and nothing that
    # could fetch it -- these instances are created with no service account, so
    # there is no cloud identity for `gcloud` or the metadata server's token
    # endpoint to use.
    #
    # `$2` is an absolute path rather than a secret name. Read it as-is; an
    # unreadable or empty file is a hard failure, because pointing vmagent at
    # an empty `-remoteWrite.bearerTokenFile` sends every sample unauthorized
    # and looks like a remote-write problem rather than a credential one.
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
