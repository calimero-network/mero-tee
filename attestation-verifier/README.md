# Attestation Verifier

Public web tool for verifying KMS and node attestations via Intel Trust Authority (ITA).

> **Full documentation**: [Components — Attestation Verifier](https://calimero-network.github.io/mero-tee/components.html)

## Deploy

Vercel with environment variables: `ITA_API_KEY`, `ITA_APPRAISAL_URL`, `NODE_ALLOWED_HOSTS`.

`NODE_ALLOWED_HOSTS` (comma-separated regexes) defaults to bare IPv4 addresses and the fleet's node names, `<name>.relay.cloud.calimero.network` and `<name>.relay.staging.cloud.calimero.network`, which mdma's manager and cloud console link here. Setting it replaces that default. Either way a host must resolve to public addresses only.

## Flow

1. Node: the user gives a node URL and the API asks it for a quote over a fresh nonce:
   `GET /attestation?nonce=<hex>&purpose=kms` (merod 1.0), else, when that is not served,
   `POST /admin-api/tee/attest` (older merod).
   KMS: mero-kms replicas are reachable only inside their VPC, so the operator calls a replica's
   `/attest` there and pastes the response (optionally with the nonce they sent).
   Or, from mdma's consoles, `/kms?kms_attest_url=…` verifies at once: the API POSTs a nonce it
   chose to that URL (mdma's manager, which relays a replica's `/attest`; hosts in
   `KMS_ATTEST_ALLOWED_HOSTS`, default `manager.cloud.calimero.network` and its staging twin) and
   checks the nonce in the quote, so the relay cannot answer with an old or invented one.
2. Quote sent to ITA for verification
3. Nonce binding and JWT verification
4. MRTD/RTMR0-3 compared with the release policy: `kms-attestation-policy.<profile>.json`
   (KMS allowlists) or `published-mrtds.json` (nodes)
5. Node only, **Keys from a verified KMS**: a merod 1.0 node reports what it verified of the
   mero-kms replica it took each key from (its storage key, and its data disk's when the image
   recorded it): the KMS's MRTD and RTMR0-3, TCB status, the signed mero-kms release and profile
   whose policy it matched, the KMS quote's SHA-256 and when. The API accepts the record only if
   the node's quote commits to it: `report_data[32..64] = SHA-256("calimero.tee-attest.kms-evidence.v1"
   ‖ attest_transport_binding(zeros, transport key) ‖ SHA-256(JCS(kms)))` (core's
   `calimero_client::attest::kms_evidence_binding`), so a relay or the host cannot substitute it,
   and the record is as trustworthy as the node's own code. The page then loads that release's
   `kms-attestation-policy.<profile>.json` itself (as `/kms` does) and checks the record's registers
   against its `kms_allowed_*` lists. A node that reports no record (older merod, or a KMS pinned by
   config rather than a release) shows the row as not checked, never failed; a record the quote does
   not commit to is "reported, not bound" and not trusted.

## Pages

- `/` — what attestation proves, and the two ways in (verify a node, verify a KMS).
- `/mero-tee?node_url=<url>&release_tag=<mero-tee tag>` — verifies a node at once (the Verify links
  of mdma's manager and cloud console); without `node_url`, a form. `nodeUrl` and `releaseTag` are
  accepted too.
- `/kms?kms_attest_url=<url>&release_tag=<mero-kms tag>&profile=<profile>` — verifies a KMS at once;
  without `kms_attest_url`, a form to paste a replica's `/attest` response. `/?kms_url=…` still
  forwards to `/kms`.
- `/agent` — a pasted mero-agent-gate `/attest` response and agent policy.
- `/docs` — the steps, the measurement registers and the terms.

A result page leads with the verdict: **Verified**, **Not verified** (a check failed) or
**Could not verify** (a required check could not run, or an error stopped the run, with what it
means and what to do). Below it, a checklist of every check the verifier makes
(`src/lib/checks.js` lists each and where it comes from); a check that did not run is shown as not
checked, never as passed. Then the measurements table (expected from the release, actual from the
quote) and the raw claims, quote, token and policy, folded, with copy buttons.

The page is plain CSS (`src/index.css`): light, or dark from the system setting.

## Development

```bash
cd attestation-verifier
npm install
npm run dev
```
