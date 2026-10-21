# mero-inference-gate

The attested TLS front of the private inference TDX image
([design](../docs/design/private-inference.md)). It runs beside vLLM in the
`inference` image role and is the only thing listening off loopback.

- **TLS ends in the TD.** The gate makes an ECDSA P-256 key and a self-signed
  certificate in memory at every start. Its quotes name the key, so a client
  that verified a quote pins it; no CA is involved.
- **`/attest`** proves which image runs (MRTD, RTMR0-3), which model
  configuration it loaded (RTMR3's second event, and the binding below), which
  TLS key is its own, and carries the H100's evidence for the same nonce.
- **`/v1/*`** goes to vLLM on `127.0.0.1:8000`, answers streamed, for callers
  whose bearer token hashes to one in the `access-token-sha256` metadata. The
  token is not passed on.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | `{"status":"ok"\|"starting","model"}`: `ok` once vLLM answers. On the measurement VM, `{"status":"ok","model":null,"measureOnly":true}` |
| `POST` | `/attest` | `{"nonceHex"}` (32 bytes) → `{"quoteB64","reportDataHex","tlsSpkiSha256","configJson","configDigest","gpuJson"}` |
| any | `/v1/*` | vLLM's OpenAI-compatible API. `401` without an accepted token, `404` on the measurement VM |

`report_data = nonce ‖ SHA-256("mero-inference-gate/attest/v1" ‖ spki_sha256 ‖
config_digest ‖ SHA-256(gpuJson or ""))`. `configJson` and `gpuJson` are the
exact bytes hashed. RTMR3 is the image event, then
`SHA-384("calimero-inference-config-v1:" ‖ hex(config_digest))`
([`attest::expected_rtmr3`](src/attest.rs)).

## Configuration

Environment variables are documented in [`src/main.rs`](src/main.rs). The image
bakes them into `/etc/mero-inference/gate.env`.

## Development

```bash
cargo test -p mero-inference-gate
cargo test -p mero-inference-gate --features mock-attestation
```
