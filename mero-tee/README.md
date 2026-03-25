# mero-tee Node Images

GCP Packer + Ansible builds for TDX Confidential VM merod node images.

> **Full documentation**: [Components — Node Images](https://calimero-network.github.io/mero-tee/components.html)

## Profiles

| Profile | Use |
|---------|-----|
| `debug` | Local/dev |
| `debug-read-only` | Integration/pre-production |
| `locked-read-only` | Production |

## Build

```bash
packer build -var-file=ubuntu-x86.pkrvars.hcl ubuntu.pkr.hcl
```

Requires Packer, Ansible, and GCP credentials.

## Release

See [Release Pipeline](https://calimero-network.github.io/mero-tee/release-pipeline.html).
