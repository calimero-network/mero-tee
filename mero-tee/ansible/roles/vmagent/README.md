# vmagent Ansible Role

This Ansible role installs vmagent (VictoriaMetrics Agent) binary and setup scripts. Actual configuration happens at runtime when the instance is deployed.

## Requirements

- Ansible 2.9+
- Ubuntu/Debian-based system
- No cloud CLI. The bearer token is a file already on the node (`provided` provider): mdma delivers it as `observability-token` metadata, and calimero-init writes it to `/etc/vector/provided_token`.

## Role Variables

See `defaults/main.yml` for all available variables:

```yaml
# vmagent version
vmagent_version: "1.132.0"

# CPU architecture (amd64, arm64)
cpu_architecture: "amd64"
```

## What This Role Does

This role **only installs** the vmagent binary and helper scripts during image build:

1. Creates `/etc/vmagent` and `/var/lib/vmagent` directories
2. Downloads vmagent v1.132.0 from GitHub releases
3. Installs vmagent to `/usr/local/bin/vmagent`
4. Copies `configure_vmagent.sh` - configures vmagent with pre-created scrape config
5. Copies `fetch_secret.sh` - bearer token fetching script

**It does NOT**:
- Create scrape configuration (done at runtime by startup script)
- Create systemd service (done at runtime by configure script)
- Fetch bearer tokens (done at runtime by configure script)

## Example Playbook

```yaml
- hosts: all
  become: true
  roles:
    - role: vmagent
      vars:
        vmagent_version: "1.132.0"
        cpu_architecture: "amd64"
```

## Runtime Configuration

After the image is built and the instance is deployed, configure vmagent in two steps:

1. **Create scrape configuration** - Define what metrics to collect
2. **Run configure script** - Set up vmagent with bearer token and systemd service

### With Authentication

```bash
#!/bin/bash

# Step 1: Create scrape configuration
cat > /etc/vmagent/scrape_config.yml <<'EOF'
global:
  scrape_interval: 15s
  external_labels:
    instance_name: "merotee-instance-1"
    instance_type: "merotee"

scrape_configs:
  - job_name: "merod"
    scrape_interval: "15s"
    static_configs:
      - targets: ["localhost:2428"]

  - job_name: "node-exporter"
    scrape_interval: "15s"
    static_configs:
      - targets: ["localhost:9100"]

  - job_name: "traefik"
    scrape_interval: "30s"
    metrics_path: "/metrics"
    static_configs:
      - targets: ["localhost:80"]
EOF

# Step 2: Configure and start vmagent
/etc/vmagent/configure_vmagent.sh \
  "/etc/vmagent/scrape_config.yml" \
  "https://victoria-lb.apps.dev.p2p.aws.calimero.network/api/v1/write" \
  "true" \
  "provided" \
  "/etc/vector/provided_token"
```

### Without Authentication (for internal VPC endpoints)

```bash
#!/bin/bash

# Step 1: Create scrape configuration
cat > /etc/vmagent/scrape_config.yml <<'EOF'
global:
  scrape_interval: 15s
  external_labels:
    instance_name: "merod-instance-1"
    instance_type: "merod"

scrape_configs:
  - job_name: "merod"
    scrape_interval: "15s"
    static_configs:
      - targets: ["localhost:2428"]
EOF

# Step 2: Configure and start vmagent (no auth)
/etc/vmagent/configure_vmagent.sh \
  "/etc/vmagent/scrape_config.yml" \
  "http://victoria-metrics-int.apps.dev.p2p.aws.calimero.network/api/v1/write" \
  "false" \
  "" \
  ""
```

### Script Parameters

The `configure_vmagent.sh` script takes 5 parameters:

1. **config_file_path** - Path to the scrape configuration YAML file
2. **remote_write_url** - VictoriaMetrics remote write endpoint
3. **auth_enabled** - "true" or "false" for bearer token authentication
4. **secret_provider** - "provided": a token file already on the node (only used if auth_enabled=true)
5. **secret_name** - Path of that token file (only used if auth_enabled=true)

The configure script will:
1. Validate scrape configuration file exists
2. Read the bearer token file (if auth enabled)
3. Create systemd service file with proper flags
4. Enable and start vmagent service

## Verification

Check that vmagent is running:

```bash
sudo systemctl status vmagent
sudo journalctl -u vmagent -f
```

Check vmagent's own metrics:

```bash
curl http://localhost:8429/metrics
```

## License

MIT

## Author

Calimero Network
