# Workflow Setup

The GCP node-image build workflow requires GitHub repo configuration. **No secrets or credentials should be committed to the repo.**

## Required GitHub Repo Variables

Configure under Settings → Secrets and variables → Actions → Variables:

| Variable | Description |
|----------|-------------|
| `GCP_PACKER_PROJECT_ID` | GCP project for Packer |
| `GCP_PACKER_REGION` | Region |
| `GCP_PACKER_ZONE` | Zone |
| `PACKER_GCP_SUBNETWORK` | Subnetwork URL |
| `GCP_ATTESTATION_PROJECT_ID` | Project for attestation VM |
| `GCP_ATTESTATION_ZONE` | Zone for attestation |
| `GCP_ATTESTATION_SUBNETWORK` | Subnetwork for attestation |
| `GCP_ATTESTATION_MACHINE_TYPE` | Machine type (e.g. c3-standard-4) |
| `GCP_ATTESTATION_ADMIN_API_PORT` | Admin API port (e.g. 80) |
| `GCP_ATTESTATION_ALLOWED_CIDRS` | CIDRs for attestation VM access |
| `GCP_ATTESTATION_CLEANUP_MAX_AGE_HOURS` | Cleanup age |
| `GCP_ATTESTATION_MEROD_VERSION` | Optional; defaults to latest core release |
| `ITA_APPRAISAL_URL` | Intel Trust Authority appraisal URL |
| `ITA_POLICY_IDS` | Policy IDs for attestation |
| `ITA_POLICY_MUST_MATCH` | Whether policy must match |

## Base image notes

Builds use the hardcoded source image family `ubuntu-2510-amd64` (Ubuntu 25.10 Questing Quokka, kernel 6.17+) for RTMR3 sysfs support. No override is allowed for release reproducibility.

**Ubuntu 26.04 LTS availability**: Based on discussions in the Ubuntu community, Ubuntu 26.04 LTS is expected to be part of the official Ubuntu repositories by March 2026, with components like authd maintained by Canonical for this release. When available, consider migrating to `ubuntu-2604-lts-amd64` for longer support.

## Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `GCP_SERVICE_ACCOUNT_KEY` | JSON key for GCP (if not using WIF) |
| OR `GCP_WORKLOAD_IDENTITY_PROVIDER` + `GCP_PACKER_SERVICE_ACCOUNT_EMAIL` | For Workload Identity Federation |
| `ITA_API_KEY` | Intel Trust Authority API key (required for quote verification and MRTD publishing) |
| `GHCR_PUSH_TOKEN` (optional) | PAT for policy promotion PR creation when `github.token` PR creation is restricted |

## Trigger

The workflow runs on push to `master` when `mero-tee/versions.json` changes.

## PR documentation guard

Pull requests that modify any of the following paths must also include a
documentation update in `docs/**` or `README.md`:

- `.github/workflows/**`
- `scripts/release/**`
- `scripts/policy/**`
- `scripts/attestation/**`
- `scripts/ci/**`
- `mero-tee/**`

This policy is enforced by `.github/workflows/docs-update-guard.yaml`.

## Release version sync guard

`release-version-sync-guard.yaml` enforces that KMS and merod release versions
are bumped together.

It validates the following are synchronized for the active release version:

- `mero-kms/Cargo.toml` package version
- `Cargo.lock` `mero-kms-phala` package version
- `mero-tee/versions.json` `imageVersion`
- `policies/index.json` release entry for that version
- `policies/kms-phala/<version>.json`
- `policies/mero-tee/<version>.json`

For `policies/index.json`, `node_image_tag` must be:

- `mero-tee-v<version>`

And `kms_tag` must be:

- `mero-kms-v<version>`

This keeps release metadata aligned with node-image release tags.

## KMS release metadata dependency on node release

`release-kms-phala.yaml` requires node policy assets from
`mero-tee-v<version>` (`published-mrtds.json`) when generating release
metadata.

On `push` runs, if the expected `mero-tee-v<version>` release is missing, the
KMS workflow checks whether a same-commit `Release mero-tee` run exists:

- if node release is actively queued/in-progress for that commit, KMS keeps
  polling;
- if no matching node release run exists and `mero-tee/versions.json` was not
  changed in the triggering push, KMS fails fast with an explicit error instead
  of waiting for the full polling timeout.

## Post-release KMS-node e2e guardrails

`post-release-kms-node-e2e.yaml` has strict release-validation behavior for
release events:

- `workflow_run` and `workflow_dispatch` operate in strict release mode
  (fail-closed).
- Node/KMS pairing defaults to same-version tags only:
  `mero-tee-vX.Y.Z` with `mero-kms-vX.Y.Z`.
- Automatic fallback to unrelated `mero-kms-v*` tags is intentionally disabled
  for release validation.
- KMS and node staging probes are dispatched on the resolved workflow ref and
  validated against an expected `headSha` before artifacts are accepted.
  - In strict release mode, probes dispatch from the immutable node release tag
    ref (`mero-tee-vX.Y.Z`) and resolve `PROBE_EXPECTED_SHA` from that tag
    commit.
  - `gh workflow run --ref` requires a named ref (branch/tag), not a raw commit
    SHA.
  - Parent e2e logs now poll child runs with status-transition output
    (queued/in_progress/completed) instead of `gh run watch` refresh spam.
- Node staging probes must also produce `node-client-verification.json`, which
  proves client-visible anti-fake checks succeeded:
  - positive quote verification passes,
  - wrong nonce is rejected,
  - tampered quote is rejected,
  - wrong expected application hash is rejected.
- Post-release KMS probes dispatch `kms-phala-staging-probe.yaml` with the same
  compose as release (single template from `scripts/phala/kms-compose-template.yaml`).
  The probe only exercises `/attest`; policy is derived from node attestation
  during the probe and published by `release-metadata` when it runs.
  - Release probes use per-profile image digests built in the current
    `release-container` job (`debug`, `debug-read-only`, `locked-read-only`)
    so attestation is validated against the exact release candidate images.
  - Probes now pass `MERO_KMS_VERSION` + `MERO_KMS_PROFILE` directly in compose,
    including pinned-image dispatches.
  - Probe compose rendering enforces that legacy `USE_ENV_POLICY` / `ALLOWED_*`
    fields are absent.
- RTMR3 policy allowlists are not used as a strict subset gate in post-release
  e2e checks. RTMR3 integrity is validated through verified attestation replay
  (event log -> RTMR3) and quote parity, matching verifier semantics.
- Post-release e2e no longer pre-fails when KMS profile policy allowlists are
  identical. Profile enforcement is validated by probe/policy subset checks,
  compose-hash parity, and runtime allow/deny behavior.
- Post-release e2e also runs an explicit cross-profile runtime negative probe:
  a `debug` node executes `merod kms probe` against a live
  `locked-read-only` KMS endpoint (kept alive briefly before cleanup), and the
  run is accepted only if that probe is rejected (expected code set includes
  `KMS_PROFILE_POLICY_REJECTED`).
  - If `merod kms probe --json` returns non-JSON terminal errors on the debug
    node, the probe step emits a structured fallback failure code
    (`MEROD_TEE_NOT_CONFIGURED` for known TEE-not-configured rejection text).
- For node staging probe dispatches in post-release e2e, `vm_machine_type`
  falls back to `c3-standard-4` when `GCP_ATTESTATION_MACHINE_TYPE` is not
  set in repository variables.
- The umbrella/index release links step publishes the `${VERSION}` release as
  non-latest (`--latest=false`) at finish so it is no longer left as a mutable
  draft.

`push` on `master` can still skip when release assets are not yet published, but
release-triggered validation is expected to fail explicitly on missing or
mismatched release inputs.
Additionally, push-triggered post-release e2e skips when the selected KMS
release tag exists but still targets an older commit; strict release-triggered
runs continue waiting/failing until commit alignment is achieved.

Workflow-level concurrency keys in this file must remain event-safe. When
combining `push`/`workflow_run` triggers, guard `github.event.workflow_run.*`
references behind an event-name check so non-`workflow_run` executions do not
fail during workflow evaluation.

## Compatibility catalog automation

`update-compatibility-catalog.yaml` runs on release publish and updates
`compatibility-catalog.json` on `master`.

- The job checks out `master` explicitly.
- Push uses `git push origin HEAD:master` so release-event detached checkouts do
  not fail during commit/push.
- Workflow concurrency is serialized (`update-compatibility-catalog-master`) to
  avoid overlapping catalog updates.

## KMS policy operations

KMS policy generation/rollout currently uses staging probes plus policy scripts.
Operationally, treat `kms-phala-staging-probe.yaml` and `scripts/policy/*.sh` as
the canonical execution path.

These operations reuse:

- `PHALA_CLOUD_API_KEY`
- `ITA_API_KEY`

## Release SBOM assets

Release workflows now install Syft and publish signed SPDX SBOM assets together
with the existing release checksums/manifest artifacts.

- `release-node-image-gcp.yaml` publishes
  `node-image-gcp-release-sbom.spdx.json` (plus matching `.sig` and `.pem`
  assets) and includes it in `node-image-gcp-checksums.txt`.
- `release-kms-phala.yaml` publishes:
  - `kms-phala-container-sbom.spdx.json`
  - `kms-phala-binaries-sbom.spdx.json`
  - matching `.sig` and `.pem` files for each SBOM

## Auto-generated release notes metadata

Release workflows generate release notes from workflow metadata and publish them
as the GitHub Release body (`body_path`).

For `release-kms-phala.yaml`, the pipeline also performs an explicit
`gh release edit --notes-file release-assets/release-notes.md` after asset
upload to guarantee the final published release body is updated, even when
GitHub release de-duplication selects a pre-existing release record for the tag.

- `release-kms-phala.yaml` includes:
  - tag and commit SHA
  - workflow run reference
  - container digest reference
  - compatibility/policy source pointers
  - verification command snippets
- `release-node-image-gcp.yaml` includes:
  - tag and commit SHA
  - workflow run reference
  - profile MRTD summary
  - verification command snippets

## Workflow modularization layout

To keep release workflows reviewable, large inline shell blocks are extracted into
versioned scripts:

- KMS release lane: `scripts/release/kms-phala/*.sh`
- Node-image release lane: `scripts/release/node-image-gcp/*.sh`

The workflows call these scripts directly, and CI runs syntax/lint checks on them.
When changing release behavior, update both the script and this documentation.

Operational note: jobs that execute repository scripts must include a checkout
step (`actions/checkout`) before invoking `bash scripts/...`.

In particular, the node-image `cleanup_attestation_resources` job must checkout
the repo before invoking `scripts/release/node-image-gcp/sweep-attestation-resources.sh`.

## Logging signal and run summary conventions

Workflow logging should prioritize fast diagnosis while avoiding repeated noise:

- Polling loops should log state/code transitions and periodic checkpoints, not
  every single attempt.
- Failure-path dumps should be bounded (for example last ~120 log lines or
  compact JSON excerpts) while preserving full artifacts for deep debugging.
- For probe/release workflows, prefer compact structured snippets in console
  output and keep full payloads in artifact files.

Current workflows following this pattern include:

- `.github/workflows/kms-phala-staging-probe.yaml`
- `.github/workflows/node-image-gcp-staging-probe.yaml`
- `.github/workflows/release-node-image-gcp.yaml`
- `.github/workflows/release-kms-phala.yaml`

Shared helper functions for these conventions live in:

- `scripts/ci/logging.sh`

Phase B/C helper utilities used by probe/release workflows:

- `scripts/ci/summary/write_workflow_summary.py` (standardized summary sections)
- `scripts/ci/artifacts/build_artifact_index.py` (artifact inventory generation)
- `scripts/ci/polling/wait_for_gcp_instance_status.py` (status polling with transition logs)
- `scripts/ci/polling/wait_for_http.py` (HTTP readiness polling with bounded logging)
- `scripts/ci/polling/wait_for_candidate_health.py` (candidate endpoint readiness selection)
- `scripts/ci/diagnostics/preview_file.py` (bounded diagnostics previews)
- `scripts/ci/probes/node_verify_anti_fake.sh` (node anti-fake verification sequence)
- `scripts/ci/probes/node_runtime_kms_probe.sh` (runtime node->KMS probe sequence)

Low-signal CI/guard workflows also emit final `GITHUB_STEP_SUMMARY` rows with
key step outcomes so operators can triage pass/fail state without scanning full
raw logs.
