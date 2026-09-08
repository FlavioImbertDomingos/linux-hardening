# Build a hardened RHEL 9 AMI from the official Red Hat marketplace AMI
# (owner 309956199498). Same flow as ubuntu2404.pkr.hcl. Separate partitions
# are not possible from a stock AMI; use rhel9.pkr.hcl (QEMU + kickstart) or
# EC2 Image Builder with a custom block-device layout when CIS 1.1.x matters.
#   packer init . && packer build -var image_version=2026.09.1 rhel9-aws.pkr.hcl

packer {
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = ">= 1.3.0"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = ">= 1.1.0"
    }
  }
}

variable "image_version" {
  type = string
}
variable "region" {
  type    = string
  default = "us-west-2"
}
variable "git_sha" {
  type    = string
  default = env("GIT_SHA")
}

source "amazon-ebs" "rhel9" {
  region          = var.region
  instance_type   = "t3.large"
  ssh_username    = "ec2-user"
  ami_name        = "base-rhel9-${var.image_version}"
  ami_description = "NIST 800-53 moderate hardened RHEL 9 (linux-hardening ${var.git_sha})"
  encrypt_boot    = true
  ena_support     = true

  source_ami_filter {
    filters = {
      name                = "RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP3"
      virtualization-type = "hvm"
      root-device-type    = "ebs"
    }
    owners      = ["309956199498"]
    most_recent = true
  }

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 20
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name             = "base-rhel9-${var.image_version}"
    HardeningProfile = "nist-800-53-moderate"
    GitSha           = var.git_sha
  }
}

build {
  sources = ["source.amazon-ebs.rhel9"]

  provisioner "ansible" {
    playbook_file           = "../playbooks/harden-image.yml"
    user                    = "ec2-user"
    use_proxy               = false
    galaxy_file             = "../requirements.yml"
    inventory_file_template = "{{ .HostAlias }} ansible_host={{ .Host }} ansible_user={{ .User }} ansible_port={{ .Port }} image_name=base-rhel9\n"
    groups                  = ["image_builders"]
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
    output     = "../artifacts/packer-manifest-rhel9.json"
    strip_path = true
    custom_data = {
      image_version = var.image_version
      git_sha       = var.git_sha
    }
  }
}
