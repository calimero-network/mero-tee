//! mero-agent-provision: the provisioner's CLI.
//!
//! ```text
//! mero-agent-provision keygen --out <secret-file>
//! mero-agent-provision attest    --gate <url> --policy <agent-policy.json>
//! mero-agent-provision provision --gate <url> --policy <agent-policy.json> \
//!                                --key <secret-file> --secrets <secrets.json>
//! ```
//!
//! `keygen` makes a provisioner's X25519 key and prints its public half, the
//! line to list in the image's `provisioners` file. `attest` verifies a gate
//! and prints the keys its quote covers; an account owner authorizes the
//! printed `signingPublicKey` as the agent's device. `provision` verifies the
//! gate the same way, then seals `secrets.json` (`{"secrets": {"NAME": "value"}}`)
//! to it. Nothing is sent before the quote passes.
//!
//! `--unauthenticated` seals without a provisioner key (debug images only);
//! `--allow-mock` accepts a mock quote (`mock-attestation` builds only).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use mero_agent_gate::keys::random_32;
use mero_agent_gate::protocol::{keypair_from_secret, SecretsBundle};
use mero_agent_gate::verify::{attest_gate, provision_gate, AgentPolicy};
use zeroize::Zeroizing;

struct Args {
    command: String,
    flags: Vec<(String, Option<String>)>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut raw = std::env::args().skip(1);
        let command = raw.next().ok_or(USAGE)?;
        let mut flags = Vec::new();
        let raw: Vec<String> = raw.collect();
        let mut i = 0;
        while i < raw.len() {
            let flag = raw[i]
                .strip_prefix("--")
                .ok_or_else(|| format!("unexpected argument '{}'", raw[i]))?
                .to_owned();
            if matches!(flag.as_str(), "unauthenticated" | "allow-mock") {
                flags.push((flag, None));
                i += 1;
            } else {
                let value = raw
                    .get(i + 1)
                    .ok_or_else(|| format!("--{flag} needs a value"))?;
                flags.push((flag, Some(value.clone())));
                i += 2;
            }
        }
        Ok(Self { command, flags })
    }

    fn value(&self, name: &str) -> Result<&str, String> {
        self.flags
            .iter()
            .find(|(flag, _)| flag == name)
            .and_then(|(_, value)| value.as_deref())
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn switch(&self, name: &str) -> bool {
        self.flags.iter().any(|(flag, _)| flag == name)
    }
}

const USAGE: &str =
    "usage: mero-agent-provision <keygen|attest|provision> [flags]; see the module docs";

fn read_policy(path: &str) -> Result<AgentPolicy, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
}

fn read_secret_key(path: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?);
    let bytes = Zeroizing::new(
        BASE64
            .decode(text.trim())
            .map_err(|_| format!("{path} is not base64"))?,
    );
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{path} is not a 32-byte key"))?;
    Ok(Zeroizing::new(key))
}

fn keygen(args: &Args) -> Result<(), String> {
    let out = args.value("out")?;
    let secret = random_32();
    let (_, public) = keypair_from_secret(&secret)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|e| format!("{out}: {e}"))?;
    file.write_all(BASE64.encode(*secret).as_bytes())
        .map_err(|e| format!("{out}: {e}"))?;
    println!("{}", BASE64.encode(public));
    Ok(())
}

async fn run(args: Args) -> Result<(), String> {
    if args.command == "keygen" {
        return keygen(&args);
    }
    if args.command != "attest" && args.command != "provision" {
        return Err(USAGE.to_owned());
    }
    let gate_url = args.value("gate")?;
    let policy = read_policy(args.value("policy")?)?;
    #[cfg(not(feature = "mock-attestation"))]
    if args.switch("allow-mock") {
        return Err("--allow-mock needs a mock-attestation build".to_owned());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())?;
    let verified = attest_gate(
        &client,
        gate_url,
        &policy,
        #[cfg(feature = "mock-attestation")]
        args.switch("allow-mock"),
    )
    .await?;
    if verified.tcb_status.as_deref() == Some("Mock") {
        eprintln!("WARNING: accepted a MOCK quote; the agent policy was not checked");
    } else {
        eprintln!("Gate verified: its quote matches the agent policy");
    }

    if args.command == "attest" {
        println!(
            "{}",
            serde_json::to_string_pretty(&verified).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    let secrets_path = args.value("secrets")?;
    let text = Zeroizing::new(
        std::fs::read_to_string(secrets_path).map_err(|e| format!("{secrets_path}: {e}"))?,
    );
    let bundle: SecretsBundle =
        serde_json::from_str(&text).map_err(|e| format!("{secrets_path}: {e}"))?;
    bundle.validate()?;
    let key = if args.switch("unauthenticated") {
        None
    } else {
        Some(read_secret_key(args.value("key")?)?)
    };
    let response = provision_gate(&client, gate_url, &verified, key.as_deref(), &bundle).await?;
    println!(
        "{}",
        serde_json::to_string(&response).map_err(|e| e.to_string())?
    );
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = match Args::parse() {
        Ok(args) => run(args).await,
        Err(e) => Err(e),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
