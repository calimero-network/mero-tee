#!/usr/bin/env bash
set -euo pipefail

vm_project="${GCP_ATTESTATION_PROJECT_ID:-${PACKER_GCP_PROJECT_ID:-${GOOGLE_CLOUD_PROJECT:-${CLOUDSDK_CORE_PROJECT:-calimero-p2p-development}}}}"
max_age_hours="${GCP_ATTESTATION_CLEANUP_MAX_AGE_HOURS:-24}"
if ! [[ "${max_age_hours}" =~ ^[0-9]+$ ]]; then
  echo "Invalid GCP_ATTESTATION_CLEANUP_MAX_AGE_HOURS='${max_age_hours}'; expected integer."
  exit 1
fi

run_prefix_regex="^tdx-(debug|debug-read-only|locked-read-only)-${GITHUB_RUN_ID}-[0-9]+$"
stale_prefix_regex="^tdx-(debug|debug-read-only|locked-read-only)-[0-9]+-[0-9]+$"
run_firewall_regex="^tee-attest-(debug|debug-read-only|locked-read-only)-${GITHUB_RUN_ID}-[0-9]+$"
stale_firewall_regex="^tee-attest-(debug|debug-read-only|locked-read-only)-[0-9]+-[0-9]+$"
cutoff_epoch="$(date -u -d "-${max_age_hours} hours" +%s)"

echo "Cleanup project: ${vm_project}"
echo "Current-run instance regex: ${run_prefix_regex}"
echo "Current-run firewall regex: ${run_firewall_regex}"
echo "Stale cleanup cutoff (hours): ${max_age_hours}"

# 1) Always sweep any instances from this workflow run across zones.
while IFS=$'\t' read -r name zone; do
  [[ -z "${name}" ]] && continue
  zone="${zone##*/}"
  echo "Deleting current-run instance: ${name} (zone=${zone})"
  gcloud compute instances delete "${name}" \
    --project "${vm_project}" \
    --zone "${zone}" \
    --delete-disks=all \
    --quiet || true
done < <(
  gcloud compute instances list \
    --project "${vm_project}" \
    --filter="name~'${run_prefix_regex}'" \
    --format='value(name,zone)' || true
)

# 2) Sweep current-run firewall rules.
while IFS= read -r rule; do
  [[ -z "${rule}" ]] && continue
  echo "Deleting current-run firewall rule: ${rule}"
  gcloud compute firewall-rules delete "${rule}" \
    --project "${vm_project}" \
    --quiet || true
done < <(
  gcloud compute firewall-rules list \
    --project "${vm_project}" \
    --filter="name~'${run_firewall_regex}'" \
    --format='value(name)' || true
)

# 3) Sweep stale orphaned instances created by this workflow naming pattern.
gcloud compute instances list \
  --project "${vm_project}" \
  --filter="name~'${stale_prefix_regex}'" \
  --format=json > /tmp/ci-tdx-instances.json || echo '[]' > /tmp/ci-tdx-instances.json
jq -r --argjson cutoff "${cutoff_epoch}" '
  .[]?
  | (.creationTimestamp | fromdateiso8601?) as $created
  | select($created != null and $created < $cutoff)
  | [.name, (.zone | split("/")[-1])]
  | @tsv
' /tmp/ci-tdx-instances.json | while IFS=$'\t' read -r name zone; do
  [[ -z "${name}" ]] && continue
  echo "Deleting stale instance: ${name} (zone=${zone})"
  gcloud compute instances delete "${name}" \
    --project "${vm_project}" \
    --zone "${zone}" \
    --delete-disks=all \
    --quiet || true
done

# 4) Sweep stale orphaned firewall rules from this workflow naming pattern.
gcloud compute firewall-rules list \
  --project "${vm_project}" \
  --filter="name~'${stale_firewall_regex}'" \
  --format=json > /tmp/ci-tdx-firewalls.json || echo '[]' > /tmp/ci-tdx-firewalls.json
jq -r --argjson cutoff "${cutoff_epoch}" '
  .[]?
  | (.creationTimestamp | fromdateiso8601?) as $created
  | select($created != null and $created < $cutoff)
  | .name
' /tmp/ci-tdx-firewalls.json | while IFS= read -r rule; do
  [[ -z "${rule}" ]] && continue
  echo "Deleting stale firewall rule: ${rule}"
  gcloud compute firewall-rules delete "${rule}" \
    --project "${vm_project}" \
    --quiet || true
done
