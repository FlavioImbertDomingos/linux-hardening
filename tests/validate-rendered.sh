#!/usr/bin/env bash
# Validates the output of tests/render-templates.yml with the real parsers.
# Requires: openssh-server, sudo, nftables, rsyslog, auditd (ausyscall), python3-yaml
set -euo pipefail
OUT="${RENDER_OUT:-/tmp/render}"
fail=0
say() { printf '%-42s %s\n' "$1" "$2"; }

for h in "$OUT"/*/; do
  h=${h%/}; n=$(basename "$h")
  if sshd -t -f "$h/ssh__sshd_config" 2>&1 | grep -vq 'privilege separation directory'; then
    say "$n sshd_config" FAIL; sshd -t -f "$h/ssh__sshd_config" || true; fail=1
  else say "$n sshd_config" ok; fi
  visudo -cf "$h/auth__sudoers-hardening" >/dev/null && say "$n sudoers" ok || { say "$n sudoers" FAIL; fail=1; }
  python3 - "$h" <<'PY' || fail=1
import sys, yaml, json, glob, os
h = sys.argv[1]
for f in ("observability__fluent-bit.yaml", "observability__otelcol-config.yaml", "sbom__grype.yaml"):
    yaml.safe_load(open(os.path.join(h, f)))
json.load(open(os.path.join(h, "sbom__manifest.json")))
print(f"{os.path.basename(h)+' yaml/json':<42} ok")
PY
done

if [ -d "$OUT/ubuntu2404" ]; then
  nft -c -f "$OUT/ubuntu2404/firewall__nftables.conf" && say "ubuntu2404 nftables" ok || { say "ubuntu2404 nftables" FAIL; fail=1; }
  if rsyslogd -N1 -f "$OUT/ubuntu2404/logging__rsyslog-hardening.conf" 2>&1 | grep -qiE 'error' ; then
    # CA file absence is expected in CI; anything else is a real error
    rsyslogd -N1 -f "$OUT/ubuntu2404/logging__rsyslog-hardening.conf" 2>&1 | grep -i error | grep -vq 'could not be accessed' && { say "ubuntu2404 rsyslog" FAIL; fail=1; } || say "ubuntu2404 rsyslog" "ok (CA file absent in CI)"
  else say "ubuntu2404 rsyslog" ok; fi
fi

# audit rules: every -S syscall must exist for its arch
python3 - "$OUT" <<'PY' || fail=1
import re, subprocess, sys, glob
out = sys.argv[1]
def table(arch):
    dump = subprocess.run(['ausyscall', arch, '--dump'], capture_output=True, text=True).stdout
    return {l.split('\t')[1].strip() for l in dump.splitlines() if '\t' in l}
t = {'b64': table('x86_64'), 'b32': table('i386')}
bad = []
for f in glob.glob(f'{out}/*/auditd__10-hardening.rules'):
    for line in open(f):
        m = re.search(r'-F arch=(b\d\d).*?-S ([\w,]+)', line)
        if m:
            bad += [(f, m.group(1), s) for s in m.group(2).split(',') if s not in t[m.group(1)]]
print(f"{'audit rules syscalls':<42} {'FAIL ' + str(bad) if bad else 'ok'}")
sys.exit(1 if bad else 0)
PY

exit $fail
