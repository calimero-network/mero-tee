# mero-tee Node Images

The node and KMS images for GCP TDX Confidential VMs, built with mkosi
(`mkosi-image/`) from the Ansible roles here (`ansible/roles`, `playbook*.yml`):
a UKI and an EROFS root behind dm-verity.

> **Full documentation**: [Components — Node Images](https://calimero-network.github.io/mero-tee/components.html)

## Profiles

| Profile | Use |
|---------|-----|
| `debug` | Local/dev |
| `debug-read-only` | Integration/pre-production |
| `locked-read-only` | Production |

## Build

```bash
sudo ROLE=node PROFILE=locked-read-only mkosi-image/build.sh OUT
```

`ROLE` is `node` or `kms`, and the KMS image takes its binary and allowlist
from environment variables (see `mkosi-image/build.sh`). Build as root, as CI
does. Requires mkosi and Python with Jinja2 and PyYAML; booting
and probing the image on GCP TDX is `node-image-mkosi.yaml`
([runbook](https://calimero-network.github.io/mero-tee/operate/runbooks/#build-the-images-with-mkosi)).

## Release

See [Release Pipeline](https://calimero-network.github.io/mero-tee/release-pipeline.html).
