//! mero-agent-gate: attestation and sealed secret provisioning for a private
//! agent TD (docs/design/private-agents.md).
//!
//! The gate runs beside the agent in the agent image. It holds no secret of
//! the agent's own logic; it proves which image runs ([`server`]'s `/attest`),
//! and takes the agent's secrets only sealed to this TD ([`protocol`]). The
//! agent can then be any program, open or closed: it reads its secrets from
//! files on the encrypted disk and signs with the key the gate attested.
//!
//! [`verify`] is the other side, for a provisioner or an account owner.

pub mod keys;
pub mod protocol;
pub mod server;
pub mod verify;

#[cfg(test)]
mod test_util;
