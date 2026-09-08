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
- [The SBOM guarantee, precisely](#the-sbom-guarantee-precisely)
- [Important defaults you may want to change](#important-defaults-you-may-want-to-change)
- [Prerequisites and caveats](#prerequisites-and-caveats)
- [Testing and CI](#testing-and-ci)
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
packer/                      example Packer templates (RHEL 9, Ubuntu 24.04) invoking the playbook
tests/render-templates.yml   renders every template for 4 synthetic hosts; CI validates with real parsers
.github/workflows/ci.yml     ansible-lint (production profile), syntax check, template validation
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

`.github/workflows/ci.yml` runs exactly that on every push and pull request. Full image builds
belong in your image pipeline (Packer / EC2 Image Builder) — see the commented `build` job in the
workflow and the templates under `packer/`.

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
