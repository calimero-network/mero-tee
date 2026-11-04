//! mero-inference-gate: the attested TLS front of a private inference TD
//! (docs/design/private-inference.md).
//!
//! The gate terminates TLS inside the TD under a key it makes at every start,
//! proves in `/attest` which image runs, which model configuration it loaded
//! and which TLS key is its own ([`attest`]), and passes `/v1/*` to vLLM on
//! loopback for callers holding an access token ([`tokens`]). A client that
//! checked a quote pins the key it names, so nobody between it and the TD,
//! the operator included, reads a prompt or an answer.

pub mod attest;
pub mod gpu;
pub mod server;
pub mod tls;
pub mod tokens;
