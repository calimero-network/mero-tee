# Migration and Implementation Plan

Step-by-step plan to migrate mero-kms-phala and GCP image build into mero-tee.

## Phase 1: Repo Setup (Done)

- Create mero-tee repo
- Add README, SECURITY.md, .gitignore
- Add MIGRATION_PLAN.md, ARCHITECTURE.md

## Phase 2: Migrate mero-kms-phala

- Copy core `mero-kms-phala` service code into `mero-tee/mero-kms`
- Configure `mero-kms/Cargo.toml` with git dependency on core
- Add rust-toolchain.toml (match core)
- Verify cargo build succeeds
- Add mero-kms-phala release workflow
- Remove mero-kms-phala from core; update core docs

## Phase 3: Migrate Packer Image Build

- Copy node-image-gcp to mero-tee/node-image-gcp
- Copy required Ansible roles
- Adjust playbook paths for ansible roles
- Copy `scripts/attestation/shared/verify_tdx_quote_ita.py` and `verify-node-image-gcp-release-assets.sh`
- Add .github/workflows/release-node-image-gcp.yaml
- Use GitHub vars/secrets for GCP config (no values in repo)

## Phase 4: Release and Signing

- Single release per version (X.Y.Z): mero-kms-phala binaries + MRTDs + attestation artifacts
- Publish mrtd-*.json, published-mrtds.json, attestation-artifacts, provenance
- Add GPG or Sigstore signing for published-mrtds.json
- Document verification steps for operators

## Phase 5: Downstream Updates

- Operators: Point published MRTDs URL to mero-tee releases
- Core: Update phala-tee-deployment.md, merod README
- Docs: Update operator-track index

## Phase 6: Cleanup

- Remove mero-kms-phala from core
- Archive or deprecate old release URLs

## Security Checklist (Before Each Commit)

- No .env, *.pem, *-key.json, *.key in repo
- No hardcoded GCP project IDs, tokens, or credentials
- .gitignore covers secrets
- Workflow uses vars. and secrets. only
