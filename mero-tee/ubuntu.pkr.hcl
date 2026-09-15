packer {
  required_plugins {
    # Pin to versions with GitHub release assets (HashiCorp moved newer releases to releases.hashicorp.com)
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = "= 1.2.1"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = "= 1.1.3"
    }
  }
}

variable "version" {
  type    = string
  default = ""
}

variable "traefik_version" {
  type    = string
  default = ""
}

variable "node_exporter_version" {
  type    = string
  default = ""
}

variable "vmagent_version" {
  type    = string
  default = ""
}

variable "vector_version" {
  type    = string
  default = ""
}

variable "instance_type" {
  type    = string
  default = ""
}

variable "cpu_architecture" {
  type    = string
  default = ""
}

variable "merod_version" {
  type    = string
  default = ""
}

variable "lockdown_profile" {
  type    = string
  default = "locked-read-only"

  validation {
    condition     = contains(["debug", "debug-read-only", "locked-read-only"], var.lockdown_profile)
    error_message = "The lockdown_profile value must be one of: debug, debug-read-only, locked-read-only."
  }
}

variable "project_id" {
  type    = string
  default = "calimero-p2p-development"
}

variable "region" {
  type    = string
  default = "europe-west4"
}

variable "zone" {
  type    = string
  default = "europe-west4-a"
}

variable "subnetwork" {
  type    = string
  default = ""
}

source "googlecompute" "this" {
  project_id           = var.project_id
  # Pinned rather than tracking a moving "latest", for release reproducibility.
  #
  # SINGLE SOURCE OF TRUTH for the base image: the CI preflight in
  # `release-node-image-gcp.yaml` reads this line rather than repeating the
  # string, so bumping the pin is a one-line change here.
  #
  # The pin must name a SUPPORTED release. Canonical delists an EOL Ubuntu from
  # `ubuntu-os-cloud`, and a delisted family fails the build outright with
  # "Source image family ... not found" — which is exactly how the whole image
  # build went down in September 2026: 25.10 (Questing) is an interim release,
  # reached EOL in July 2026, and took its family with it. Hence an LTS: an
  # interim release buys nine months and then does this again.
  #
  # Kernel: RTMR3 sysfs support needs 6.17+ (see `calimero-init.sh.j2`, which
  # reads `tdx_guest/measurements/` on 6.17+ and falls back to `tdx_guest/mr/`).
  # 26.04 LTS ships well past that bar.
  source_image_family  = "ubuntu-2604-lts-amd64"
  source_image_project_id = ["ubuntu-os-cloud"]
  disable_default_service_account = true
  zone                 = var.zone
  region               = var.region
  # The PUBLISHED name and family are a cross-repo contract and deliberately do
  # NOT track the base release. mdma's dispatcher resolves images by these exact
  # prefixes (`tee_image_name_prefix` / `tee_image_family_prefix` in
  # `dispatcher/app/config.py`), as does
  # `scripts/release/node-image-gcp/resolve-image-vm-parameters.sh`, so renaming
  # them here alone would leave the dispatcher unable to find any image. They
  # still read "questing-25-10" after the base moved to 26.04 LTS; renaming needs
  # a paired mdma change and a deploy ordering, so it is not done here.
  image_name           = "merotee-ubuntu-questing-25-10-${var.lockdown_profile}-${replace(var.version, ".", "-")}"
  image_family         = "merotee-ubuntu-questing-${var.lockdown_profile}"
  image_description    = "MeroTEE ${var.lockdown_profile} profile image based on Ubuntu 26.04 LTS (Resolute Raccoon) with Traefik and mero-auth. Name retains the questing-25-10 prefix for dispatcher compatibility."
  machine_type         = var.instance_type
  disk_size            = 20
  disk_type            = "pd-ssd"
  subnetwork           = var.subnetwork != "" ? var.subnetwork : null
  ssh_username         = "ubuntu"
  tags                 = ["packer", "merotee"]
}

build {
  sources = ["source.googlecompute.this"]

  provisioner "ansible" {
    playbook_file   = "playbook.yml"
    ansible_env_vars = [
      "ANSIBLE_CONFIG=ansible.cfg"
    ]
    extra_arguments = [
      "--scp-extra-args", "'-O'",
      "-e", "cpu_architecture=${var.cpu_architecture}",
      "-e", "lockdown_profile=${var.lockdown_profile}",
      "-e", "merod_version=${var.merod_version}",
      "-e", "traefik_version=${var.traefik_version}",
      "-e", "node_exporter_version=${var.node_exporter_version}",
      "-e", "vmagent_version=${var.vmagent_version}",
      "-e", "vector_version=${var.vector_version}",
    ]
  }
}
