# Example: build a hardened RHEL 9 QCOW2 with Packer + QEMU from a kickstart that
# lays out the CIS/STIG partition scheme, then run the playbook.
#   packer init . && packer build -var image_version=2026.09.1 -var iso_url=... rhel9.pkr.hcl

packer {
  required_plugins {
    qemu    = { source = "github.com/hashicorp/qemu", version = ">= 1.1.0" }
    ansible = { source = "github.com/hashicorp/ansible", version = ">= 1.1.0" }
  }
}

variable "image_version" { type = string }
variable "iso_url" { type = string }
variable "iso_checksum" { type = string }
variable "git_sha" { type = string, default = env("GIT_SHA") }

source "qemu" "rhel9" {
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  output_directory = "output-rhel9"
  vm_name          = "base-rhel9-${var.image_version}.qcow2"
  format           = "qcow2"
  disk_size        = "30G"
  memory           = 4096
  cpus             = 2
  accelerator      = "kvm"
  headless         = true
  ssh_username     = "builder"
  ssh_private_key_file = "~/.ssh/packer_builder"
  ssh_timeout      = "30m"
  shutdown_command = "sudo shutdown -P now"
  http_directory   = "http"
  boot_wait        = "5s"
  boot_command = [
    "<up><tab> inst.text inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/rhel9-ks.cfg<enter>"
  ]
}

build {
  sources = ["source.qemu.rhel9"]

  provisioner "ansible" {
    playbook_file = "../playbooks/harden-image.yml"
    user          = "builder"
    use_proxy     = false
    galaxy_file   = "../requirements.yml"
    inventory_file_template = "{{ .HostAlias }} ansible_host={{ .Host }} ansible_user={{ .User }} ansible_port={{ .Port }} image_name=base-rhel9\n"
    groups        = ["image_builders"]
    extra_arguments = [
      "-e", "image_version=${var.image_version}",
      "-e", "image_git_sha=${var.git_sha}",
      "-e", "sbom_export_dir=${path.cwd}/../artifacts",
      "-e", "finalize_remove_build_user=true",   # break-glass access is via cloud-init keys, not this account
    ]
    ansible_env_vars = ["ANSIBLE_HOST_KEY_CHECKING=False", "ANSIBLE_CONFIG=../ansible.cfg"]
  }

  post-processor "manifest" {
    output      = "../artifacts/packer-manifest-rhel9.json"
    custom_data = { image_version = var.image_version, git_sha = var.git_sha }
  }
}
