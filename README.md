# linux-hardening

**NIST SP 800-53 Rev. 5 (Moderate) hardened Linux base images with SBOM guarantees — as an Ansible playbook.**

[![CI](https://github.com/FlavioImbertDomingos/linux-hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/FlavioImbertDomingos/linux-hardening/actions/workflows/ci.yml)
![Ansible](https://img.shields.io/badge/ansible--core-%E2%89%A5%202.15-black)
![RHEL](https://img.shields.io/badge/RHEL-8%20%7C%209-red)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-orange)
![NIST](https://img.shields.io/badge/NIST%20800--53-Rev.5%20Moderate-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Turns a stock **RHEL 8/9** (or Rocky/Alma) or **Ubuntu 22.04/24.04** VM into a sealed, verifiable
base image. Every task is tagged with the NIST control it implements (`nist_AU-12`, `nist_SC-7`, …),
the build **fails unless the image proves it**, and the SBOM, vulnerability report, OpenSCAP
evidence and signed manifest ship both inside the image and next to it.

```
 fresh VM ──► preflight ──► 11 hardening roles ──► reboot ──► verify (~60 asserts)
          ──► SBOM + vuln gate + attestation ──► OpenSCAP ──► finalize (seal) ──► image
```

## Contents

- [What it does](#what-it-does)
- [Layout](#layout)
- [Quick start](#quick-start)
- [Try it locally in 15 minutes](#try-it-locally-in-15-minutes)
- [The SBOM guarantee, precisely](#the-sbom-guarantee-precisely)
- [Important defaults you may want to change](#important-defaults-you-may-want-to-change)
- [Prerequisites and caveats](#prerequisites-and-caveats)
- [Testing and CI](#testing-and-ci)
- [Building a real image](#building-a-real-image)
- [Versions](#versions)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## What it does

* **Kernel-level security** — hardened sysctl set (~60 keys), 40-module denylist, boot-time flags
  (`lockdown`, `init_on_alloc/free`, `page_alloc.shuffle`, `slab_nomerge`, `vsyscall=none`,
  `pti=on`, `audit=1`, …), core dumps off, RHEL crypto-policy `DEFAULT:NO-SHA1` (or FIPS),
  SELinux enforcing / AppArmor enforce.
* **Auditing** — auditd with an architecture-aware, NIST-mapped rule set (~190 rules), immutable
  (`-e 2`), privileged-command coverage generated from the actual SUID/SGID inventory, optional
  audisp-remote, syslog mirror.
* **Secure SSH** — keys only, root login off, all forwarding off, modern KEX/ciphers/MACs
  (post-quantum hybrid KEX where OpenSSH supports it), ed25519 + RSA-4096 host keys only, weak
  moduli removed, host keys regenerated per instance on first boot.
* **Log management** — persistent, sealed journald; rsyslog with 0640 files; optional
  syslog-over-TLS (RFC 5425) forwarding; 90-day rotation.
* **Observability** — pre-wired `node_exporter` (loopback by default) → on-host
  **OpenTelemetry Collector** (hostmetrics + Prometheus + OTLP) → your gateway; **Fluent Bit**
  ships journald, `audit.log` and `sudo.log` through the same collector. The image name, version,
  git SHA and SBOM digest ride along as OTel resource attributes.
* **SBOM guarantees** — Syft SBOM (SPDX, CycloneDX, Syft JSON) of the *entire* root filesystem;
  Grype scan that **fails the build on High/Critical with a fix**; `rpm -Va`/`debsums` package
  integrity; unsigned-RPM detection; cosign-signed manifest and in-toto SPDX attestation; the
  tools themselves are checksum- and Sigstore-verified before use. Vulnerability counts are
  published as Prometheus metrics from inside the image.
* **Compliance evidence** — OpenSCAP evaluation against SCAP Security Guide (CIS L1 by default,
  any SSG profile or tailoring file), HTML/ARF reports exported with the SBOM.
* **Verification** — `playbooks/verify.yml` asserts ~60 controls after reboot (sshd -T values,
  sysctl, live kernel cmdline, MAC state, services, permissions, root lock, audit flags) and can be
  re-run against a running fleet to detect drift.
* **Sealing** — AIDE baseline initialised *last*, `/etc/image-release` provenance stamp, host keys
  and machine-id regenerated on first boot, build residue and NOPASSWD sudo removed.

The full control-to-task matrix is in [`docs/controls-map.md`](docs/controls-map.md).

## Layout

```
playbooks/harden-image.yml   preflight → roles → reboot → verify → sbom+compliance → finalize
playbooks/verify.yml         standalone drift check for running instances
inventory/group_vars/all.yml cross-cutting knobs (endpoints, CIDRs, gate policy, FIPS)
roles/
  baseline      package hygiene, GPG enforcement, auto security updates, chrony, psacct
  kernel        sysctl, module denylist, GRUB cmdline, core dumps, crypto policy / FIPS
  mac           SELinux enforcing + booleans | AppArmor enforce-all
  filesystem    tmpfs /tmp noexec, /dev/shm, bind /var/tmp, perms, SUID strip, cron allow-lists, umask
  auth          login.defs, pwquality, faillock, pwhistory (authselect / pam-auth-update), sudo, banners, TMOUT
  ssh           drop-in or full sshd_config, modern KEX/ciphers (PQ hybrid where available), host keys, moduli
  firewall      firewalld drop zone (RHEL) | nftables default-deny (Ubuntu), admin/monitoring CIDRs
  auditd        auditd.conf, 10-hardening.rules, 20-privileged.rules (generated), 99-finalize (-e 2)
  logging       journald, rsyslog, logrotate, optional TLS forwarding
  aide          config + daily systemd timer (DB built by finalize)
  observability node_exporter, otelcol-contrib, fluent-bit (checksum-verified downloads)
  sbom          cosign → syft → grype, package integrity, gate, sign/attest, export
  compliance    OpenSCAP + SSG, score threshold, report export
  finalize      provenance stamp, AIDE init, cleanup, first-boot key regeneration
docs/controls-map.md         NIST control → role/task matrix
packer/                      Packer templates: ubuntu2404 + rhel9-aws (AMI), rhel9 (QEMU + kickstart)
tests/local-vm.sh            end-to-end run against a throwaway Multipass VM
tests/render-templates.yml   renders every template for 4 synthetic hosts; CI validates with real parsers
.github/workflows/ci.yml     ansible-lint (production profile), syntax check, template + packer validation
.github/workflows/build-image.yml  manual AMI build via Packer + AWS OIDC
LICENSE                      MIT
```

## Quick start

```bash
pip install ansible ansible-lint
ansible-galaxy collection install -r requirements.yml

# 1. point the inventory at a fresh VM (Packer normally does this)
vi inventory/hosts.yml

# 2. set endpoints, CIDRs, signing key (or use -e / vault)
vi inventory/group_vars/all.yml

# 3. build
export IMAGE_VERSION=2026.09.1 GIT_SHA=$(git rev-parse --short HEAD) GITHUB_TOKEN=...
ansible-playbook playbooks/harden-image.yml -l rhel9-image

# artefacts land in ./artifacts/<host>/ : SBOMs, vulns.{json,txt,sarif}, manifest.json(+.sig/.bundle),
#                                        spdx.attestation.bundle, OpenSCAP report.html / arf.xml
```

Run a single control family, e.g. everything that implements AU-12:

```bash
ansible-playbook playbooks/harden-image.yml -l rhel9-image --tags nist_AU-12
```

Check a running fleet for drift (read-only):

```bash
ansible-playbook playbooks/verify.yml -i prod-inventory.yml
```

## Try it locally in 15 minutes

You don't need AWS, Packer or a real server to see the playbook work. `tests/local-vm.sh`
launches a throwaway Ubuntu VM on your own machine with [Multipass](https://multipass.run),
runs the whole pipeline against it (harden → reboot → verify → SBOM gate → OpenSCAP → seal),
and leaves the evidence in `artifacts/`.

### What you need

| | macOS (Intel or Apple Silicon) | Linux |
|---|---|---|
| Multipass | `brew install --cask multipass` | `sudo snap install multipass` |
| Ansible ≥ 2.15 | `brew install ansible` | `pip install ansible` |
| Free resources | 2 CPUs, 4 GB RAM, 20 GB disk for the VM | same |
| Network | outbound HTTPS to GitHub, Ubuntu mirrors, packages.fluentbit.io, Anchore DB | same |

Apple Silicon builds an **aarch64** image; the playbook supports it (arm64 tool downloads,
aarch64-safe audit rules). Everything below is identical on x86_64.

### Steps

```bash
# 1. get the code
git clone https://github.com/FlavioImbertDomingos/linux-hardening.git
cd linux-hardening
ansible-galaxy collection install -r requirements.yml

# 2. build and harden a VM (first run downloads the Ubuntu image; ~10-15 min total)
tests/local-vm.sh                 # Ubuntu 24.04 (default)
tests/local-vm.sh 22.04           # or Ubuntu 22.04
```

The script generates an SSH key (`~/.ssh/linux-hardening-test`), launches a VM named
`lh-ubuntu2404`, writes an inventory to `inventory/local-lh-ubuntu2404.yml` (next to
`group_vars/`, so the defaults apply), and runs
`playbooks/harden-image.yml`. You will see the plays go by in order:

```
PLAY [Preflight]                              OS check, controller IP detected
PLAY [Harden operating system]                11 roles, ~250 tasks
PLAY [Reboot so kernel, MAC and mount changes are live]
PLAY [Verify hardened state]                  ~60 assertions must pass
PLAY [Software bill of materials, vulnerability gate and compliance scan]
PLAY [Finalise image]                         AIDE baseline, cleanup, seal
```

A successful run ends with `failed=0` for the host and a line like
`base-ubuntu2404-test v0.0.0-local finalised — AIDE_DB_SHA256=…; SEALED`.

### Look at the results

```bash
ls artifacts/lh-ubuntu2404/
#   base-ubuntu2404-test-0.0.0-local.spdx-json.json      SBOM (SPDX)
#   base-ubuntu2404-test-0.0.0-local.cyclonedx-json.json SBOM (CycloneDX)
#   base-ubuntu2404-test-0.0.0-local.vulns.txt           Grype findings, human readable
#   base-ubuntu2404-test-0.0.0-local.vulns.sarif         same, for code-scanning tools
#   base-ubuntu2404-test-0.0.0-local.manifest.json       tool versions, counts, gate result, hashes
#   base-ubuntu2404-test-0.0.0-local.report.html         OpenSCAP report (open in a browser)

# inside the VM
multipass shell lh-ubuntu2404
  cat /etc/image-release             # provenance stamp
  sudo auditctl -l | wc -l           # ~190 audit rules loaded
  sudo auditctl -s | grep enabled    # enabled 2 = immutable
  sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|kexalgorithms'
  cat /proc/cmdline                  # lockdown=integrity init_on_alloc=1 ... audit=1
  sudo aa-status | head -3           # AppArmor profiles enforced
  sudo nft list ruleset | head -40   # default-deny firewall
  systemctl status auditd otelcol-contrib fluent-bit node_exporter --no-pager
  curl -s localhost:9100/metrics | grep ^image_vulnerabilities
  sudo ls /var/lib/sbom              # the same evidence, shipped in the image
```

One deliberate difference from a real image build: the script keeps password-less sudo for the
`ubuntu` account after the seal (`finalize_strip_build_user_nopasswd=false`) so that the
`verify` and `--tags` re-runs below still work. Packer builds strip it.

### Iterate

```bash
tests/local-vm.sh 24.04 verify          # re-run only the ~60 drift assertions (seconds)
tests/local-vm.sh 24.04 build --tags ssh,firewall   # re-apply selected roles
tests/local-vm.sh 24.04 destroy         # throw the VM away
```

Try tightening or loosening a default (for example `sbom_fail_on: critical` or
`auditd_log_all_execve: true` in `inventory/group_vars/all.yml`), destroy, and run again.

### If something fails

* **`Vulnerability gate failed`** — the base image has a High/Critical CVE with a fix that the
  Ubuntu mirror hasn't caught up with yet. Read `artifacts/…/vulns.txt`; either wait for the
  update, add a documented entry to `sbom_vuln_ignore`, or run once with
  `-e sbom_enforce=false` to see the rest of the pipeline.
* **Verify assertions fail on kernel cmdline** — the VM did not reboot (check
  `hardening_reboot: true`) or GRUB did not regenerate; `multipass shell` and run
  `sudo update-grub`, then `tests/local-vm.sh 24.04 verify`.
* **Download errors from GitHub (403 / rate limit)** — export `GITHUB_TOKEN=<personal token>`
  before running; the tool installers use it for the releases API.
* **`multipass launch` hangs on macOS** — first launch needs the Ubuntu image (~600 MB); also
  confirm Multipass is allowed under *System Settings → Privacy & Security*.
* Anything else: the failing task name tells you the role and NIST control; rerun with `-vv`
  appended (`tests/local-vm.sh 24.04 build -vv`).

## The SBOM guarantee, precisely

1. **Tool trust** — `cosign` is downloaded and sha256-checked, then verifies its *own* Sigstore
   release signature. `cosign verify-blob` then checks the keyless signatures on the `syft` and
   `grype` checksum files (certificate identity pinned to Anchore's release workflow, OIDC issuer
   pinned to GitHub Actions) before their tarballs are checksum-verified and installed.
2. **Package integrity** — every RPM must carry a GPG signature (`sbom_fail_on_unsigned_packages`);
   `rpm -Va` / `debsums --changed` must show no modified package-managed binaries (files the
   hardening changes on purpose are allow-listed in `sbom_integrity_allowlist`).
3. **Inventory** — `syft scan dir:/` over the whole root filesystem (proc/sys/dev/run/tmp/log
   excluded) produces SPDX 2.3, CycloneDX 1.x and Syft JSON, tagged with `image_name`/`image_version`.
4. **Gate** — `grype` scans the SBOM with a fresh DB; the build **fails** on any finding at
   `sbom_fail_on` (default `high`) or above that has a fix (`sbom_only_fixed: true`). Accepted risks
   go in `sbom_vuln_ignore` with a reason and expiry and are recorded in the manifest.
5. **Attestation** — `<image>.manifest.json` records tool versions, DB build date, counts by
   severity, gate result, accepted risks, integrity findings and sha256 of every artefact. It and
   both SBOMs are signed with `cosign sign-blob` (key file, KMS URI, or keyless), plus an in-toto
   `spdxjson` attestation bundle. Private keys never persist on the build host.
6. **Evidence in the image** — `/var/lib/sbom/` (root, 0750) keeps everything; `/etc/image-release`
   carries the manifest and SPDX digests (the AIDE DB digest sits in `/var/lib/aide/aide.db.gz.sha256`); node_exporter exposes
   `image_vulnerabilities{severity=…}` so Prometheus can alert when an image ages.
7. **Evidence off the image** — everything is fetched to `artifacts/<host>/` for the pipeline to
   archive next to the AMI/QCOW.

Verify later, from anywhere:

```bash
cosign verify-blob --key cosign.pub --signature base-rhel9-1.0.0.manifest.json.sig base-rhel9-1.0.0.manifest.json
sha256sum -c <(jq -r '.artifacts | to_entries[] | "\(.value)  \(.key)"' base-rhel9-1.0.0.manifest.json)
```

## Important defaults you may want to change

| Variable | Default | Why you might change it |
|---|---|---|
| `hardening_admin_cidrs` / `hardening_monitoring_cidrs` | `10.0.0.0/8` | firewall allow-lists for SSH / 9100 |
| `ssh_password_authentication` | `"no"` | keys only; cloud-init injects keys |
| `node_exporter_listen` | `127.0.0.1:9100` | set `0.0.0.0:9100` for direct Prometheus scrapes |
| `otel_exporter_endpoint` | `otel-gateway.example.internal:4317` | your OTLP gateway |
| `sbom_fail_on` / `sbom_only_fixed` | `high` / `true` | gate strictness |
| `sbom_cosign_key` / `sbom_cosign_keyless` | unset | attestation is skipped (warned) until set |
| `kernel_fips_enabled` | `false` | FIPS 140-3 mode (RHEL) / Ubuntu Pro FIPS |
| `kernel_lockdown_mode` | `integrity` | `confidentiality` blocks /dev/mem, kprobes, some BPF |
| `kernel_restrict_user_namespaces` | `false` | `true` breaks rootless containers |
| `mac_selinux_booleans` `deny_execmem` | `false` | `true` breaks JIT runtimes |
| `filesystem_tmp_as_tmpfs` (noexec) | `true` | installers that exec from /tmp will fail |
| `auditd_log_all_execve` | `false` | log every user command (very verbose) |
| `auditd_admin_space_left_action` | `SUSPEND` | `HALT` for high-impact systems (AU-5(2)) |
| `compliance_profile` | CIS L1 server | `ospp`, `cui`, `stig`, or a tailoring file |
| `compliance_min_score` | `0` | fail below N % once you have a tailoring file |
| `finalize_remove_build_user` | `false` | remove the Packer account entirely |

## Prerequisites and caveats

* A **fresh** VM with a sudo-capable build account (Packer's default). The account keeps
  `NOPASSWD` until `finalize` strips it and locks the password.
* Outbound HTTPS to `github.com`, `packages.fluentbit.io`, distro mirrors and the Grype DB
  (`toolbox-data.anchore.io`). For air-gapped builds pin all `*_version`, set `sbom_grype_db_url`
  to a mirror and pre-stage the tarballs in `/var/lib/hardening/staging`.
* Separate partitions (`/var`, `/var/log`, `/var/log/audit`, `/home`, `/tmp`) must come from the
  image build (see `packer/`); the `filesystem` role only tightens options on what exists.
* The reboot in the middle of `harden-image.yml` is required for kernel cmdline, MAC and mount
  changes to be *verified* live; `hardening_reboot: false` skips it (verify will then fail on
  cmdline assertions).
* Set `hardening_is_container: true` (auto-detected) to exercise the roles inside a container (e.g. a molecule scenario you add);
  kernel, mount, firewall and service-start tasks are skipped there.
* OpenSCAP: some rules (partitioning, GRUB password, FIPS) cannot pass on single-disk cloud images.
  Start with `compliance_min_score: 0`, review `artifacts/<host>/*.report.html`, then encode
  waivers in a tailoring file and raise the threshold.

## Testing and CI

No target VM is needed to validate a change:

```bash
ansible-lint                                   # production profile, must be clean
ansible-playbook --syntax-check playbooks/harden-image.yml
RENDER_OUT=/tmp/render ansible-playbook tests/render-templates.yml   # 4 synthetic hosts
sudo RENDER_OUT=/tmp/render bash tests/validate-rendered.sh          # sshd -t, visudo -c, nft -c, rsyslogd -N1, audit syscall tables, YAML/JSON
```

`.github/workflows/ci.yml` runs exactly that on every push and pull request, plus `packer validate`
on the templates under `packer/`.

## Building a real image

CI proves the playbook is well-formed; only a real VM exercises the reboot, the verify play, the
Grype gate and the OpenSCAP scan. Three ways, cheapest first.

**1. Local throwaway VM (Multipass, ~15 min, free)** — see
[Try it locally in 15 minutes](#try-it-locally-in-15-minutes) above.

**2. AWS AMI from GitHub Actions (manual, ~25 min)** — `Actions → build-image → Run workflow`,
pick `ubuntu2404` or `rhel9-aws`. One-time setup in *Settings → Secrets and variables*:

| Name | Kind | Purpose |
|---|---|---|
| `AWS_ROLE_ARN` | secret | IAM role trusted by GitHub OIDC (`token.actions.githubusercontent.com`) with EC2 + AMI permissions |
| `AWS_REGION` | variable | defaults to `us-west-2` |
| `COSIGN_KEY` / `COSIGN_PASSWORD` | secret | optional — enables SBOM signing |

The run uploads `artifacts/` (SBOM, scan, compliance report, Packer manifest with the AMI id).

**3. Packer from your workstation** — same templates, your own AWS credentials:

```bash
cd packer && packer init .
packer build -var image_version=2026.09.1 ubuntu2404.pkr.hcl
packer build -var image_version=2026.09.1 rhel9-aws.pkr.hcl
# RHEL 9 with the CIS partition layout (QEMU + kickstart, needs KVM and a RHEL ISO):
packer build -var image_version=2026.09.1 -var iso_url=... -var iso_checksum=sha256:... rhel9.pkr.hcl
```

In every case the host running Ansible is detected in the preflight play and allowed through the
firewall for the duration of the build only; the finalize play removes that allowance so the
shipped image trusts nothing but `hardening_admin_cidrs`.

## Versions

Pinned in role defaults and checked September 2026: syft 1.51.0, grype 0.97.2, cosign 3.1.3,
node_exporter 1.12.1; otelcol-contrib and SSG content resolve to `latest` (pin for reproducible
release builds). Fluent Bit comes from the official package repository.

## Contributing

Pull requests are welcome. Keep the bar the CI enforces: `ansible-lint` production profile clean,
every new task tagged with the NIST control(s) it implements, every new template covered by
`tests/render-templates.yml`, and anything OS-specific branched on `ansible_os_family` for both
RHEL 8/9 and Ubuntu 22.04/24.04. If you change a hardening default, say why in the PR and update
[`docs/controls-map.md`](docs/controls-map.md).

## Security

This playbook configures security controls but is not itself a security boundary: review the
defaults against your own threat model before production use. To report a vulnerability in the
playbook, open a private security advisory on this repository rather than a public issue.

## License

[MIT](LICENSE) — © 2026 PulseAI Systems.
