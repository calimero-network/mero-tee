#!/bin/bash
# fetch_secret.sh
# Usage: ./fetch_secret.sh <provider> <secret_name>
#
# Providers: gcp, provided
# Example: ./fetch_secret.sh gcp vmagent-bearer-token

set -euo pipefail

PROVIDER="$1"
SECRET_NAME="$2"

case "$PROVIDER" in
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
    # Secret Manager over its REST API, with the access token taken from the
    # metadata server -- curl and python3 only, and no `gcloud`.
    #
    # On GCP Ubuntu images `gcloud` ships as a snap, and locked-read-only masks
    # snapd (merod-lockdown, R8), so a snap binary is either missing from PATH
    # or dies on confinement. This provider used to shell out to it, which made
    # it a path that worked on debug images and silently failed on production
    # ones (mero-tee#339). Both tools used here are debs the image already
    # depends on; the conformance role asserts neither resolves into /snap.
    #
    # `$2` is a secret id in this instance's project, or a full
    # `projects/<p>/secrets/<id>` name, and the latest version is read -- the
    # same two forms and the same version `gcloud --secret` took.
    #
    # The instance still needs a service account holding
    # `roles/secretmanager.secretAccessor`. mdma creates nodes with none, which
    # is why they use `provided` instead; on such a node the token request below
    # is the step that fails, and it says so.
    METADATA="http://metadata.google.internal/computeMetadata/v1"
    if ! TOKEN_JSON=$(curl -sSf --max-time 10 -H "Metadata-Flavor: Google" \
        "$METADATA/instance/service-accounts/default/token"); then
      echo "gcp: no access token from the metadata server; does this instance have a service account?" >&2
      exit 1
    fi
    ACCESS_TOKEN=$(printf '%s' "$TOKEN_JSON" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

    case "$SECRET_NAME" in
      projects/*/secrets/*) SECRET_RESOURCE="$SECRET_NAME" ;;
      *)
        PROJECT_ID=$(curl -sSf --max-time 10 -H "Metadata-Flavor: Google" \
          "$METADATA/project/project-id")
        SECRET_RESOURCE="projects/$PROJECT_ID/secrets/$SECRET_NAME"
        ;;
    esac

    # The bearer header goes in on stdin (`-H @-`), not argv, so the access
    # token never appears in this process's command line for `ps` to show.
    # `payload.data` is base64; the decoded bytes are written as-is, with no
    # trailing newline added.
    printf 'Authorization: Bearer %s\n' "$ACCESS_TOKEN" \
      | curl -sSf --max-time 20 -H @- \
          "https://secretmanager.googleapis.com/v1/${SECRET_RESOURCE}/versions/latest:access" \
      | python3 -c 'import base64,json,sys; sys.stdout.buffer.write(base64.b64decode(json.load(sys.stdin)["payload"]["data"]))'
    ;;

  *)
    echo "Unknown provider: $PROVIDER" >&2
    echo "Supported providers: gcp, provided" >&2
    exit 1
    ;;
esac
