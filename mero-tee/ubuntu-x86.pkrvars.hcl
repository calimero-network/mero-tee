# Packer build VM: n2-standard-2 (no TDX needed for build host; widely available).
# Output image runs on c3-standard-4 at runtime (Intel TDX confidential compute; probe, MDMA).
instance_type = "n2-standard-2"
# x86_64 for image build/naming; "intel" reserved for confidential compute (TDX) context
cpu_architecture = "x86"
