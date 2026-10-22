# Design: private inference on GCP TDX + H100

Status: prototype. Built and unit-tested here; not yet booted on an H100. The
release measures it best effort, as the agent image was at first.

A fourth TDX image role, `inference`: an OpenAI-compatible model server (vLLM)
in a confidential VM with an H100 in confidential-computing mode. mero-bot can
then send prompts to a model nobody else can read, run by us, instead of only
to NEAR AI Cloud ([private agents](private-agents.md), "The agent: mero-bot on
NEAR AI Cloud"). It is the "GPU TD of our own" that design had parked.

## At a glance

- **One image, any model.** The image holds the engine, not the weights.
  Whoever runs the VM names the model in instance metadata: a Hugging Face
  repository, an immutable revision, and the SHA-256 of its weights. The TD
  downloads them, refuses them unless they hash to that value, and binds the
  whole configuration into every quote. Changing the model is a new VM, not a
  new image or release.
- **Clients verify the engine and the model.** A quote names the image
  (MRTD, RTMR0-2, and RTMR3's image event, as for every role) and the model
  configuration (a second RTMR3 event). A client checks both before it sends a
  prompt, and the GPU's own evidence with NVIDIA.
- **TLS ends in the TD.** The gate's TLS key is generated in the TD at every
  start and bound into its quotes, so a client pins the key a verified quote
  names. Nobody between, the operator included, reads a prompt or an answer.
- **No KMS.** The TD keeps no secrets across boots: the weights are public and
  hash-checked, and its scratch disk is encrypted under a key it makes at boot
  and forgets at power-off.

## Image and boot

`ROLE=inference`, built from `playbook-inference.yml` by the same mkosi build
(`mero-tee/mkosi-image/build.sh`), with a dm-verity root like every role:

- the shared base (`cleanup`, `merod-lockdown` on `locked-read-only`, the log
  and metric shippers);
- the NVIDIA open kernel modules, prebuilt for the image's `linux-image-gcp`
  (`linux-modules-nvidia-<n>-server-open-gcp`), and the matching user space,
  from the same archive snapshot as the rest of the image (`nvidia_driver_branch`);
- vLLM and its Python dependencies, installed by `build.sh` from
  `mero-tee/inference/requirements.lock` (every wheel pinned by SHA-256) into
  `/opt/mero-inference/site-packages`, for the image's own Python;
- `mero-inference-gate`, `inference-init` and their units.

Image name and family `merotee-inference-<profile>-<version>` and
`merotee-inference-<profile>`. It runs on `a3-highgpu-1g` (one H100) or larger
a3 shapes, as a TDX confidential VM. RTMR0 depends on the VM's shape, so the
release measures it on the shape it publishes for.

**Boot (`inference-init`)**

1. Extend RTMR3 with `calimero-rtmr3-v3:inference:<profile>:<roothash>`, the
   same block as every role, fatal on `locked-read-only`.
2. Observability, as on the agent: only `inference-init` and the gate are
   shipped. vLLM's own journal never leaves the TD, and it runs with request
   logging off.
3. Read and validate the model configuration from metadata (below), write it
   canonically to `/run/mero-inference/config.json`, and extend RTMR3 with
   `SHA-384("calimero-inference-config-v1:" ‖ hex(SHA-256(config.json)))`.
   Fatal on `locked-read-only` if the extend fails. Metadata `measure-only=true`
   skips this step and everything after it, so the release can measure the
   image on a VM with no model (it then serves `/attest` only).
4. Check the GPU: confidential-computing mode on (fatal on `locked-read-only`),
   verify it locally against NVIDIA's reference measurements
   (`nv-local-gpu-verifier`), and only then set its ready state, so no work
   reaches a GPU that failed.
5. Open the scratch disk (the GCE disk named `model`) as LUKS2 with
   HMAC-SHA256 integrity under a random key generated in the TD and never
   written. `model-store=memory` uses a tmpfs instead (small models).
6. Download the weights with `huggingface_hub` at the pinned revision, hash
   them (below), and refuse to go on unless the digest is `model-sha256`.
7. Start vLLM on `127.0.0.1:8000` (offline: `HF_HUB_OFFLINE=1`, no usage
   stats), then the gate.

### Model configuration (instance metadata)

| Key | Required | Value |
| --- | --- | --- |
| `model-repo` | yes | Hugging Face repository, `owner/name` |
| `model-revision` | yes | 40-hex commit SHA (a branch or tag could move) |
| `model-sha256` | yes | weights digest, below |
| `served-model-name` | no | the name clients ask for; default the repo's name, lowercased |
| `engine-args` | no | JSON object of allowlisted vLLM flags, below |
| `access-token-sha256` | yes | comma-separated hex SHA-256 of the bearer tokens the gate accepts |
| `hf-token` | no | Hugging Face token, for gated repositories |
| `model-store` | no | `disk` (default) or `memory` |
| `measure-only` | no | `true`: the release's measurement VM |
| `logs-endpoint`, `metrics-endpoint`, `observability-token` | no | as on every role |

Metadata is written by whoever runs the VM, so every value is validated, and
`trust-remote-code` cannot be turned on: a repository's Python never runs.

**Engine arguments** (`engine-args`), each optional:
`max-model-len`, `max-num-seqs`, `max-num-batched-tokens`,
`tensor-parallel-size`, `seed` (integers); `gpu-memory-utilization` (0.1-0.98);
`dtype` (`auto`, `bfloat16`, `float16`); `quantization` (`fp8`, `awq`,
`awq_marlin`, `gptq`, `gptq_marlin`, `compressed-tensors`); `kv-cache-dtype`
(`auto`, `fp8`, `fp8_e4m3`, `fp8_e5m2`); `enable-prefix-caching`,
`enable-auto-tool-choice`, `enforce-eager` (booleans); `tool-call-parser`,
`reasoning-parser` (`[a-z0-9_]{1,40}`); `generation-config` (`auto`, `vllm`).

**Canonical configuration.** `config.json` is
`json.dumps(obj, sort_keys=True, separators=(",", ":"))` of:

```json
{"engine":{"max-model-len":32768},"repo":"Qwen/Qwen3-8B","revision":"<40 hex>",
 "schema":1,"servedModelName":"qwen3-8b","weightsSha256":"<64 hex>"}
```

Its SHA-256 is the **config digest**. The access tokens, the Hugging Face token
and the store are not in it: they change who may call and where bytes sit, not
what answers.

**Weights digest.** Every file the download keeps (`*.safetensors`, `*.json`,
`*.model`, `*.tiktoken`, `*.txt`, `*.jinja`, `*.py` is never kept), sorted by
path: `SHA-256` of the lines `"<sha256 hex>  <relative path>\n"`.
`scripts/inference/model-digest.py <dir>` computes it on a local snapshot
(`hf download <repo> --revision <sha> --local-dir <dir>`); the TD runs the same
code.

## The gate: `mero-inference-gate`

HTTPS on port 8443, under an ECDSA P-256 key and self-signed certificate made
in memory at every start. Clients trust the key a verified quote names, not a
CA.

| Method | Path | |
| --- | --- | --- |
| `GET` | `/health` | `{"status":"ok"\|"starting","model":<served name>}`; `ok` once vLLM answers |
| `POST` | `/attest` | `{"nonceHex": <64 hex>}` → the answer below |
| any | `/v1/*` | proxied to vLLM, streaming included, with `Authorization: Bearer <token>` whose SHA-256 is in `access-token-sha256`. `401` otherwise. With no tokens configured, every call is refused |

**`/attest`**

```json
{
  "quoteB64": "...",
  "reportDataHex": "...",
  "tlsSpkiSha256": "<hex SHA-256 of the certificate's SubjectPublicKeyInfo DER>",
  "configJson": "<config.json, exactly the bytes hashed>",
  "configDigest": "<hex SHA-256(configJson)>",
  "gpuJson": "<NVIDIA evidence, exactly the bytes hashed, or null>"
}
```

`report_data = nonce (32 bytes) ‖ SHA-256("mero-inference-gate/attest/v1" ‖
spki_sha256 (32) ‖ config_digest (32) ‖ SHA-256(gpuJson, or empty))`.

`gpuJson` is the payload NVIDIA's NRAS takes (`POST /v3/attest/gpu`):
`{"nonce": <nonceHex>, "arch": "HOPPER", "evidence_list": [{"certificate":
<base64>, "evidence": <base64>}]}`, collected fresh for the request's nonce.
It is `null` only on a TD with no GPU, which a client refuses.

## What a client checks (mero-bot `attest: "mero"`)

1. `POST /attest` over TLS with a fresh 32-byte nonce; the connection's SPKI
   SHA-256 must equal `tlsSpkiSha256`.
2. The quote verifies with DCAP, is not a debug TD, its TCB status is allowed.
3. MRTD and RTMR0-2 are in the signed `kms-inference-attestation-policy.<profile>.json`
   lists. RTMR3 equals `SHA-384(base ‖ SHA-384("calimero-inference-config-v1:" ‖
   configDigest))` for some `base` in `allowed_rtmr3` (the image event alone,
   which the release measured with `measure-only`).
4. `report_data` is as above; `configDigest = SHA-256(configJson)`.
5. The configuration serves the model the profile asks for, and, if the
   profile pins one, has the pinned config digest.
6. `gpuJson`'s nonce is this nonce, and NRAS accepts it
   (`x-nvidia-overall-att-result`).
7. Every request goes over a connection whose SPKI is the attested one.

## Release

`release-kms.yaml` gains `inference-image`, best effort like `agent-image`:
build, boot on `INFERENCE_VM_MACHINE_TYPE` (default `a3-highgpu-1g`) in the
first of the `INFERENCE_VM_ZONE` zones that has one free (default
`us-central1-a us-east5-a europe-west4-c`, the zones GCP offers H100s as TDX VMs
in; H100s run out per zone, and a zone without quota fails fast) with `measure-only=true`, take the quote, and publish
`kms-inference-attestation-policy.<profile>.json` (`"role": "inference"`, the
agent policy's shape) on `mero-kms-v<version>`, signed with the rest. The KMS
image does not serve it: an inference TD asks the KMS for nothing. A failed or
unschedulable GPU probe leaves the release without an inference policy and
never blocks it.

## mdma

Admins create **inference hosts** (model, revision, digest, engine arguments,
machine shape); the dispatcher starts the VM with that metadata, a scratch
disk, and a bearer token it generates (kept Fernet-encrypted, only its hash in
metadata). A cloud agent's owner can pick a running inference host at claim:
the console verifies the host's signed policy, writes a `mero` profile into the
sealed `MERO_AGENTS_JSON`, and mdma seals the host's token to the agent gate as
the operator secret `MERO_INFERENCE_API_KEY`, as it does the NEAR key.

## Trust that remains and risks

Everything in the KMS and agent designs, plus:

- **NVIDIA.** The GPU's firmware and its attestation service (NRAS), and the
  driver's confidential-computing implementation.
- **The weights' publisher.** The digest proves which weights run, not that
  they behave.
- **Python supply chain.** Every wheel is pinned by hash and measured; the
  image runs exactly them, and they are as trustworthy as their publishers.
- **Who may call.** Access tokens control cost, not confidentiality: the
  operator chooses them and can read their hashes.

| Risk | Effect | Mitigation |
| --- | --- | --- |
| No a3 capacity at release | No inference policy that release | Best effort; reuse a previous release's hosts |
| A model's chat template or tool parser misbehaves | Bad answers, not leaked prompts | Pinned in the digest; pick another model |
| Operator points agents at a host serving another model | The client refuses: the quote names the configuration | Check 5 |
