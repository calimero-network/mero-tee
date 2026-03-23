# Packer build VM: n2-standard-2 (no TDX needed for build host; widely available).
# Output image runs on c3-standard-4 at runtime (Intel TDX confidential compute; probe, MDMA).
instance_type = "n2-standard-2"
# Third-party releases (Traefik, vmagent, node-exporter) use amd64 for x86_64; calimero-core maps amd64->x86_64
cpu_architecture = "amd64"
