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
    # The token was handed to this node by mdma over the attested fleet channel
    # and written to disk by the sidecar. Nothing to fetch: it is already here,
    # and there is no cloud identity on these instances to fetch it with.
    #
    # `$2` is the token file's absolute path. Read it as-is; an
    # unreadable or empty file is a hard failure, because configuring vector
    # with an empty Authorization header would send every log line unauthorized
    # and look like a sink problem rather than a credential one.
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
