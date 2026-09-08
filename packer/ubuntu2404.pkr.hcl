# Example: build a hardened Ubuntu 24.04 AMI with Packer, running the playbook
# through the ansible provisioner. Adjust source AMI / region / subnet.
#   packer init . && packer build -var image_version=2026.09.1 ubuntu2404.pkr.hcl

packer {
  required_plugins {
    amazon  = { source = "github.com/hashicorp/amazon", version = ">= 1.3.0" }
    ansible = { source = "github.com/hashicorp/ansible", version = ">= 1.1.0" }
  }
}

variable "image_version" { type = string }
variable "region" { type = string, default = "us-west-2" }
variable "git_sha" { type = string, default = env("GIT_SHA") }

source "amazon-ebs" "ubuntu2404" {
  region        = var.region
  instance_type = "t3.large"
  ssh_username  = "ubuntu"
  ami_name      = "base-ubuntu2404-${var.image_version}"
  ami_description = "NIST 800-53 moderate hardened Ubuntu 24.04 (linux-hardening ${var.git_sha})"
  encrypt_boot  = true          # SC-28(1)
  ena_support   = true

  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
      virtualization-type = "hvm"
      root-device-type    = "ebs"
    }
    owners      = ["099720109477"]
    most_recent = true
  }

  # Separate partitions cannot be created from a cloud AMI without a custom
  # disk layout; use an image-builder / kickstart / autoinstall flow if you
  # need /var, /var/log, /var/log/audit, /home, /tmp on their own volumes (CIS 1.1.x).
  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 20
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name             = "base-ubuntu2404-${var.image_version}"
    HardeningProfile = "nist-800-53-moderate"
    GitSha           = var.git_sha
  }
}

build {
  sources = ["source.amazon-ebs.ubuntu2404"]

  provisioner "ansible" {
    playbook_file   = "../playbooks/harden-image.yml"
    user            = "ubuntu"
    use_proxy       = false
    galaxy_file     = "../requirements.yml"
    inventory_file_template = "{{ .HostAlias }} ansible_host={{ .Host }} ansible_user={{ .User }} ansible_port={{ .Port }} image_name=base-ubuntu2404\n"
    groups          = ["image_builders"]
    extra_arguments = [
      "-e", "image_version=${var.image_version}",
      "-e", "image_git_sha=${var.git_sha}",
      "-e", "sbom_export_dir=${path.cwd}/../artifacts",
      "-e", "finalize_remove_build_user=false",
    ]
    ansible_env_vars = [
      "ANSIBLE_HOST_KEY_CHECKING=False",
      "ANSIBLE_CONFIG=../ansible.cfg",
    ]
  }

  post-processor "manifest" {
    output     = "../artifacts/packer-manifest-ubuntu2404.json"
    strip_path = true
    custom_data = { image_version = var.image_version, git_sha = var.git_sha }
  }
}
