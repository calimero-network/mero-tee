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

variable "source_image" {
  type    = string
  default = ""
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
  source_image         = var.source_image != "" ? var.source_image : null
  # ubuntu-2510-amd64 is Canonical's standard x86_64 image family (Intel TDX uses x86_64)
  source_image_family  = var.source_image == "" ? "ubuntu-2510-amd64" : null
  source_image_project_id = ["ubuntu-os-cloud"]
  disable_default_service_account = true
  zone                 = var.zone
  region               = var.region
  image_name           = "merotee-ubuntu-questing-25-10-${var.lockdown_profile}-${replace(var.version, ".", "-")}"
  image_family         = "merotee-ubuntu-questing-${var.lockdown_profile}"
  image_description    = "MeroTEE ${var.lockdown_profile} profile image based on Ubuntu 25.10 (Questing Quokka, kernel 6.17+) with Traefik and mero-auth"
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
