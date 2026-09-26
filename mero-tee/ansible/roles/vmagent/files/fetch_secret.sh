#!/bin/bash
# fetch_secret.sh
# Usage: ./fetch_secret.sh <provider> <token_file>
#
# Providers: provided
# Example: ./fetch_secret.sh provided /etc/vector/provided_token

set -euo pipefail

PROVIDER="$1"
TOKEN_FILE="$2"

case "$PROVIDER" in
  provided)
    # The token is already on this machine: either stamped as instance metadata
    # at creation and written out by calimero-init, or delivered later over the
    # attested fleet channel by the sidecar. Nothing to fetch, and nothing that
    # could fetch it -- these instances are created with no service account, so
    # there is no cloud identity for `gcloud` or the metadata server's token
    # endpoint to use.
    #
    # `$2` is the token file's absolute path. Read it as-is; an
    # unreadable or empty file is a hard failure, because pointing vmagent at
    # an empty `-remoteWrite.bearerTokenFile` sends every sample unauthorized
    # and looks like a remote-write problem rather than a credential one.
    if [[ ! -s "$TOKEN_FILE" ]]; then
      echo "provided token file $TOKEN_FILE is missing or empty" >&2
      exit 1
    fi
    cat "$TOKEN_FILE"
    ;;


  *)
    echo "Unknown provider: $PROVIDER" >&2
    echo "Supported providers: provided" >&2
    exit 1
    ;;
esac
