# NIST SP 800-53 Rev. 5 (Moderate) — control-to-implementation map

Every task in the playbook carries a `nist_<ID>` tag. Run `ansible-playbook playbooks/harden-image.yml --list-tasks --tags nist_AU-9`
to see exactly which tasks implement a control, or `--tags nist_AU-9` to apply only those. The table below is the
human-readable index. Controls not listed (PE-*, PS-*, PL-*, most of IR-*, CP-*) are organisational and out of scope
for an OS image; where an image can only *support* a control (e.g. IR-4 via audit data) it is noted.

| Control | Title | Implemented by | Evidence |
|---|---|---|---|
| **AC-2, AC-2(4)** | Account management, automated audit actions | `auth` (aging, INACTIVE, nologin shells), `auditd` (identity watches), `finalize` (build account) | audit key `identity`, `verify.yml` UID-0 / empty-password asserts |
| **AC-3** | Access enforcement | `mac` (SELinux enforcing / AppArmor enforce), `filesystem` (perms), `auditd` (perm_mod, access) | `getenforce`, `aa-status --json` in verify |
| **AC-6, AC-6(9), AC-6(10)** | Least privilege, audit privileged functions, prevent non-privileged execution | `filesystem` (SUID strip, cron allow-lists, umask 027), `auth` (sudo use_pty/logfile, pam_wheel su), `auditd` (priv_esc, privileged, root_cmd, setuid_exec) | sudo.log, audit keys `privileged`, `priv_esc` |
| **AC-7** | Unsuccessful logon attempts | `auth` (faillock deny=5, unlock 900s, even_deny_root) | `/etc/security/faillock.conf` |
| **AC-8** | System use notification | `auth` (`/etc/issue`, `/etc/issue.net`), `ssh` (`Banner`), `baseline` (empty MOTD) | verify banner presence |
| **AC-10** | Concurrent session control | `auth` (`maxlogins`) | `/etc/security/limits.d/99-maxlogins.conf` |
| **AC-11, AC-12** | Session lock / termination | `auth` (`TMOUT=900` readonly), `ssh` (`ClientAliveInterval 300`, `CountMax 1`) | `sshd -T` in verify |
| **AC-17, AC-17(2)** | Remote access, crypto protection | `ssh` (keys only, root login off, forwarding off, modern KEX/ciphers/MACs, `AllowGroups`), `firewall` (admin CIDRs) | `sshd -T`, nft/firewalld rules |
| **AU-2, AU-3, AU-3(1)** | Event logging, content of records | `auditd` (`log_format ENRICHED`, `--loginuid-immutable`, full rule set) | `auditctl -l` ≥ 40 rules in verify |
| **AU-4, AU-4(1)** | Storage capacity, transfer to alternate storage | `auditd` (max_log_file/num_logs, audisp-remote), `logging` (journald caps, rsyslog TLS forward), `observability` (Fluent Bit → OTel, persistent queues) | `auditd.conf`, `journald.conf.d`, Fluent Bit storage |
| **AU-5, AU-5(1)** | Response to logging failures | `auditd` (`space_left_action SYSLOG`, `admin_space_left_action SUSPEND`, `disk_full_action SUSPEND`, `-f 1`) | `auditd.conf` |
| **AU-6, AU-6(4)** | Review, analysis, central review | `auditd` syslog plugin, `observability` (all logs to OTel gateway) | OTel logs pipeline |
| **AU-8** | Time stamps | `baseline` (chrony, UTC), `auditd` (time-change rules), `logging` (RSYSLOG_FileFormat) | `chronyc tracking` |
| **AU-9, AU-9(2), AU-9(3)** | Protection of audit information, off-host backup, crypto protection | `auditd` (0700 log dir, rules immutable `-e 2`, tool watches), `logging` (0640 logs, journald `Seal=yes`), `aide` (AUDITTOOLS sha512 rule) | `auditctl -s` enabled=2 in verify |
| **AU-11** | Record retention | `logging` (90-day logrotate, journald 1 month), `sbom`/`compliance` exports | `logrotate.d/00-hardening` |
| **AU-12** | Audit record generation | `auditd` (all rule files), `baseline` (psacct), `kernel` (`audit=1 audit_backlog_limit=8192`) | `/proc/cmdline` in verify |
| **AU-14** | Session audit (optional) | `auth` (`auth_sudo_iolog`), `auditd` (`auditd_log_all_execve`) | sudo I/O logs |
| **CA-2, CA-7** | Assessments, continuous monitoring | `compliance` (OpenSCAP + SSG), `verify.yml` re-runnable against fleet, `aide` daily timer | `report.html`, `arf.xml` |
| **CM-5, CM-5(1)** | Access restrictions for change | `auditd` (software_mgmt, kernel/boot config, systemd, cron watches), `baseline` (GPG enforcement) | audit keys `software_mgmt`, `boot`, `modules` |
| **CM-6** | Configuration settings | every role; `compliance` measures the result | OpenSCAP score |
| **CM-7, CM-7(1)** | Least functionality | `baseline` (package/service removal), `kernel` (module denylist), `filesystem` (noexec mounts), `firewall` (default deny), `logging` (no listeners) | verify forbidden-service asserts |
| **CM-8** | System component inventory | `sbom` (SPDX/CycloneDX of full rootfs), `/etc/image-release` | `/var/lib/sbom/*.spdx-json.json` |
| **CM-11** | User-installed software | `auditd` (pip/snap/dpkg/rpm exec watches), `filesystem` (noexec /tmp, /var/tmp, /dev/shm) | audit key `software_mgmt` |
| **IA-2, IA-2(1)** | Identification & authentication | `ssh` (`AuthenticationMethods publickey`), `auth` (root password locked) | `sshd -T`, `passwd -S root` |
| **IA-4** | Identifier management | `auth` (`INACTIVE=35`), `auditd` identity watches | `/etc/default/useradd` |
| **IA-5, IA-5(1)** | Authenticator management, password-based | `auth` (pwquality minlen 15 / 4 classes, SHA512 100k rounds, history 5, aging) | `pwquality.conf`, `login.defs` |
| **IA-5(2)** | Public-key based | `ssh` (ed25519 / RSA-4096 host keys, DSA/ECDSA removed, moduli ≥ 3071) | verify weak-host-key find |
| **MP-2, MP-6** | Media access, sanitisation | `kernel` (usb-storage/firewire/thunderbolt denylist), `auditd` (mounts), `finalize` (residue removal) | audit key `mounts` |
| **RA-5, RA-5(2)** | Vulnerability monitoring, update by frequency | `sbom` (grype gate, fresh DB, metrics), `baseline` (auto security updates) | `*.vulns.json`, `image_vulnerabilities` metric |
| **SC-4** | Information in shared resources | `finalize` (logs, histories, machine-id, host keys cleared) | `/etc/machine-id` empty at build end |
| **SC-5** | Denial-of-service protection | `kernel` (syncookies, rp_filter, rfc1337), `firewall` (SSH/ICMP rate limits) | `sysctl` verify |
| **SC-7, SC-7(5)** | Boundary protection, deny by default | `firewall` (input policy drop, forward drop), `kernel` (no redirects/source route, `ip_forward 0`) | nft/firewalld rules |
| **SC-8, SC-8(1)** | Transmission confidentiality/integrity | `ssh` (AEAD ciphers, ETM MACs), `logging` (syslog TLS), `observability` (OTLP TLS, min 1.2), `kernel` (OpenSSL TLS1.2+/SECLEVEL 2 on Ubuntu) | configs |
| **SC-10** | Network disconnect | `ssh` (ClientAlive*) | `sshd -T` |
| **SC-12** | Key establishment/management | `ssh` (`RekeyLimit`, fresh host keys), `finalize` (first-boot host key regeneration) | `ssh-hostkeys-regen.service` |
| **SC-13** | Cryptographic protection | `kernel` (crypto-policies / FIPS), `ssh` (algorithm lists, PQ hybrid KEX), `aide` (sha256+sha512) | `update-crypto-policies --show` |
| **SC-28** | Protection of information at rest | `kernel` (core dumps off) — disk encryption is an image-build/cloud concern | `coredump.conf.d` |
| **SC-39** | Process isolation | `kernel` (`kptr_restrict`, `ptrace_scope`, `unprivileged_bpf_disabled`, `pti=on`, user namespaces optional), `mac` | `sysctl` verify |
| **SC-41** | Port and I/O device access | `kernel` (usb-storage, firewire, thunderbolt, bluetooth denylist) | `modprobe -n -v` verify |
| **SC-45** | System time synchronisation | `baseline` (chrony, iburst, no server mode) | `chrony.conf` |
| **SI-2, SI-2(2)** | Flaw remediation, automated status | `baseline` (full upgrade at build, dnf-automatic / unattended-upgrades security), `sbom` gate | `image_vulnerabilities_fixable` metric |
| **SI-4** | System monitoring | `observability` (node_exporter, hostmetrics, OTLP), `auditd` (susp_activity), `firewall` (drop logging) | OTel metrics pipeline |
| **SI-7, SI-7(1), SI-7(15)** | Software/information integrity, integrity checks, code authentication | `aide` (baseline + daily check), `sbom` (checksum + Sigstore verification of tools, rpm -Va/debsums, cosign attestation), `baseline` (gpgcheck), `kernel` (`module.sig_enforce` optional, Secure Boot report) | AIDE DB digest in `/etc/image-release` |
| **SI-16** | Memory protection | `kernel` (`randomize_va_space 2`, `init_on_alloc/free`, `page_alloc.shuffle`, `slab_nomerge`, `randomize_kstack_offset`, `vsyscall=none`, `mmap_min_addr`, core dumps off), `mac` (execmem/execstack booleans) | `/proc/cmdline` verify |
| **SR-3, SR-4, SR-4(4), SR-11** | Supply chain controls, provenance, component authenticity | `sbom` (signed SBOM + manifest + in-toto attestation, tool signature verification, unsigned package detection) | `*.manifest.json.sig`, `*.spdx.attestation.bundle` |

## Supporting (not implementing) controls

* **IR-4 / IR-5** — audit, sudo, journald and OTel streams give responders the data; alerting lives in your platform.
* **AU-7** — audit reduction is done centrally (OTel gateway / SIEM); `aureport`/`ausearch` remain available on-host.
* **CP-9** — SBOM and compliance artefacts are exported to the controller for archival with the image.
* **SC-28(1)** — full-disk / volume encryption must be enabled by the cloud platform or Packer disk layout.
