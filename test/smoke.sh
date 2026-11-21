#!/usr/bin/env bash
set -euo pipefail

PACKAGE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/server-audit-test.XXXXXX")
trap 'rm -rf "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/bin" "$TEST_DIR/source/etc" "$TEST_DIR/source/var/lib/dpkg" "$TEST_DIR/tmp"
mkdir -p "$TEST_DIR/work/server-audit-report"
printf 'existing report\n' > "$TEST_DIR/work/server-audit-report/keep.txt"
cd "$TEST_DIR/work"
export TEST_DIR
export PACKAGE_DIR
export TMPDIR="$TEST_DIR/tmp"
export PATH="$TEST_DIR/bin:$PATH"
export AUDIT_HOST=test.invalid AUDIT_USER=audit AUDIT_SSH_PRIVATE_KEY=TEST-ONLY
export AUDIT_GRYPE=grype
unset AUDIT_FAIL_ON_REBOOT
printf 'ID=debian\nVERSION_ID="12"\n' > "$TEST_DIR/source/etc/os-release"
cp "$PACKAGE_DIR/test/fixtures/status" "$TEST_DIR/source/var/lib/dpkg/status"
tar -cf "$TEST_DIR/inventory.tar" -C "$TEST_DIR/source" etc/os-release var/lib/dpkg/status

cat > "$TEST_DIR/bin/ssh" <<'SH'
#!/usr/bin/env bash
set -eu
[[ -z "${AUDIT_SSH_PRIVATE_KEY:-}" ]]
if [[ "${SSH_FAILURE:-0}" = 1 ]]; then exit 255; fi
if [[ "${*: -1}" = 'tar -chf - -C / etc/os-release var/lib/dpkg/status' ]]; then
    cat "$TEST_DIR/inventory.tar"
else
    cat >/dev/null
    printf 'Running kernel: %s\n' "${RUNNING_KERNEL-7.0.0-38-generic}"
    echo "Reboot required: ${REBOOT:-NO}"
fi
SH
cat > "$TEST_DIR/bin/grype" <<'SH'
#!/usr/bin/env bash
set -eu
if [[ "$1" = version ]]; then exit 0; fi
echo 'Scanner progress: all findings including ignored matches'
echo 'Scanner warning: test diagnostic' >&2
if [[ "${GRYPE_STATUS:-0}" = 1 ]]; then echo 'Scanner error: database failure' >&2; fi
snapshot=${1#dir:}
[[ "$snapshot" = "$TMPDIR"/server-audit.*/snapshot ]]
grep -q '^Source: openssl (3.0.11-1~deb12u2)$' "$snapshot/var/lib/dpkg/status"
grep -q '^Status: hold ok installed$' "$snapshot/var/lib/dpkg/status"
if grep -q removed-package "$snapshot/var/lib/dpkg/status"; then exit 1; fi
printf '%s\n' "$snapshot" > "$TEST_DIR/last-snapshot"
cp "$snapshot/var/lib/dpkg/status" "$TEST_DIR/last-status"
# Model package discovery and severity gating using only the supplied snapshot.
sed -n 's/^Package: //p' "$snapshot/var/lib/dpkg/status" > "$TEST_DIR/scanned-packages"
report="$TEST_DIR/scanner-report.json"
if [[ "${GRYPE_BAD_JSON:-0}" = 1 ]]; then printf '{}\n' > "$report";
elif [[ "${GRYPE_STATUS:-0}" = 2 ]]; then
    jq --rawfile packages "$TEST_DIR/scanned-packages" --arg cve "${GRYPE_CVE:-}" '
        .matches |= map(select(.artifact.name as $name | $packages | split("\n") | index($name))) |
        if $cve == "" then . else .matches |= map(select(.vulnerability.id == $cve)) end
    ' "$PACKAGE_DIR/test/fixtures/grype.json" > "$report"
else printf '{"matches": []}\n' > "$report"; fi
config_next=0
threshold_next=0
threshold=high
for argument in "$@"; do
    if [[ "$config_next" = 1 ]]; then cp "$argument" "$TEST_DIR/last-config"; config_next=0; fi
    if [[ "$threshold_next" = 1 ]]; then threshold=$argument; threshold_next=0; fi
    case "$argument" in
        --config) config_next=1 ;;
        --fail-on) threshold_next=1 ;;
        json=*) cp "$report" "${argument#json=}" ;;
        table) echo 'Full Grype CVE table'; jq -r '.matches[].vulnerability.id' "$report" ;;
    esac
done
if [[ "${GRYPE_STATUS:-0}" = 1 ]]; then exit 1; fi
if [[ "${GRYPE_BAD_JSON:-0}" != 1 ]] && jq -e --arg threshold "$threshold" '
    def rank: {unknown: 0, negligible: 1, low: 2, medium: 3, high: 4, critical: 5}[ascii_downcase];
    any(.matches[]; (.vulnerability.severity | rank) >= ($threshold | rank))
' "$report" >/dev/null; then exit 2; fi
SH
chmod +x "$TEST_DIR/bin/ssh" "$TEST_DIR/bin/grype"

check_run() {
    local name=$1 expected=$2 status=0
    shift 2
    "$PACKAGE_DIR/server-audit.sh" "$@" > "$TEST_DIR/$name.log" 2>&1 || status=$?
    if [[ "$status" != "$expected" ]]; then cat "$TEST_DIR/$name.log"; echo "FAIL $name: $status, expected $expected" >&2; exit 1; fi
    [[ -z "$(ls -A "$TMPDIR")" ]]
    [[ "$(ls -A "$TEST_DIR/work" | sed '/^\.grype\.yaml$/d')" = server-audit-report ]]
    [[ "$(cat "$TEST_DIR/work/server-audit-report/keep.txt")" = 'existing report' ]]
    echo "PASS $name"
}
check_run success 0
grep -qx 'Excluded inactive kernel packages: 5 (not running; use --verbose to list).' "$TEST_DIR/success.log"
if grep -q '^Package: linux-image-7.0.0-38-lowlatency$' "$TEST_DIR/last-status"; then exit 1; fi
for prefix in linux-image linux-image-unsigned linux-modules linux-modules-extra; do
    grep -qx "Package: $prefix-7.0.0-38-generic" "$TEST_DIR/last-status"
    if grep -qx "Package: $prefix-7.0.0-31-generic" "$TEST_DIR/last-status"; then exit 1; fi
done
for package in linux-image-generic linux-tools-7.0.0-31-generic linux-libc-dev linux-modules-vendor-7.0.0-31-generic; do
    grep -qx "Package: $package" "$TEST_DIR/last-status"
done
first_snapshot=$(cat "$TEST_DIR/last-snapshot")
check_run repeated-run 0
[[ "$(cat "$TEST_DIR/last-snapshot")" != "$first_snapshot" ]]
grep -qx 'Total: 0 package/advisory matches. Full CVE list: --verbose.' "$TEST_DIR/repeated-run.log"
grep -qx 'Scanner progress: all findings including ignored matches' "$TEST_DIR/repeated-run.log"
grep -qx 'Scanner warning: test diagnostic' "$TEST_DIR/repeated-run.log"
grep -qx 'Reboot required: NO' "$TEST_DIR/repeated-run.log"
grep -qx 'ignore: \[\]' "$TEST_DIR/last-config"
printf '# Project policy\nignore: []\n' > .grype.yaml
check_run project-config 0
cmp .grype.yaml "$TEST_DIR/last-config"
printf '# Custom policy\nignore: []\n' > "$TEST_DIR/custom policy.yaml"
export AUDIT_GRYPE_CONFIG="$TEST_DIR/custom policy.yaml"
check_run explicit-config 0
cmp "$AUDIT_GRYPE_CONFIG" "$TEST_DIR/last-config"
export AUDIT_GRYPE_CONFIG="$TEST_DIR/missing.yaml"
check_run missing-config 1
grep -q '^Cannot read Grype config:' "$TEST_DIR/missing-config.log"
unset AUDIT_GRYPE_CONFIG
rm .grype.yaml
# An inactive Critical finding must neither appear nor fail, even in verbose mode.
GRYPE_STATUS=2 GRYPE_CVE=CVE-kernel-fixed check_run inactive-kernel-only 0 --verbose
grep -qx '  linux-modules-7.0.0-31-generic 7.0.0-31.31' "$TEST_DIR/inactive-kernel-only.log"
if grep -Eq 'CVE-kernel-fixed|Threshold exceeded' "$TEST_DIR/inactive-kernel-only.log"; then exit 1; fi
# Booting that exact release makes the same finding count again.
GRYPE_STATUS=2 GRYPE_CVE=CVE-kernel-fixed RUNNING_KERNEL=7.0.0-31-generic check_run old-kernel-now-running 2
grep -Fq 'linux-modules-7.0.0-31-generic 7.0.0-31.31 [running kernel]' "$TEST_DIR/old-kernel-now-running.log"
GRYPE_STATUS=2 GRYPE_CVE=CVE-kernel-open check_run running-kernel-only 2
GRYPE_STATUS=2 GRYPE_CVE=CVE-qemu-open check_run userspace-only 2
GRYPE_STATUS=2 GRYPE_CVE=CVE-qemu-open AUDIT_FAIL_ON=critical check_run configured-threshold 0
for invalid_kernel in '' 'two releases' $'7.0.0-38-generic\nRunning kernel: 7.0.0-31-generic'; do
    rm -f "$TEST_DIR/last-snapshot"
    RUNNING_KERNEL="$invalid_kernel" check_run invalid-kernel 1
    grep -qx 'Missing or invalid running kernel release' "$TEST_DIR/invalid-kernel.log"
    [[ ! -f "$TEST_DIR/last-snapshot" ]]
done
export REBOOT=YES
check_run reboot-default 3
AUDIT_FAIL_ON_REBOOT=0 check_run reboot-opt-out 0
grep -qx 'Reboot required: YES' "$TEST_DIR/reboot-opt-out.log"
AUDIT_FAIL_ON_REBOOT=0 check_run reboot-policy 3 --fail-on-reboot
export GRYPE_STATUS=2
check_run vulnerabilities 2
grep -q 'coreutils 9.5: 1 advisory, highest Medium; fixed in 9.7' "$TEST_DIR/vulnerabilities.log"
if grep -Fq 'linux-modules-7.0.0-31-generic' "$TEST_DIR/vulnerabilities.log"; then exit 1; fi
grep -Fq 'linux-modules-7.0.0-38-generic 7.0.0-38.38 [running kernel]' "$TEST_DIR/vulnerabilities.log"
grep -qx 'Published fixes (1 packages):' "$TEST_DIR/vulnerabilities.log"
grep -qx 'No published fix, high or higher (2 packages):' "$TEST_DIR/vulnerabilities.log"
grep -q '1 without affected-version bounds' "$TEST_DIR/vulnerabilities.log"
grep -qx 'Other findings without published fixes: 1.' "$TEST_DIR/vulnerabilities.log"
grep -qx 'Threshold exceeded: high or higher (including findings without fixes).' "$TEST_DIR/vulnerabilities.log"
if grep -Eq 'CVE-|Full Grype CVE table' "$TEST_DIR/vulnerabilities.log"; then exit 1; fi
grep -qx 'Scanner progress: all findings including ignored matches' "$TEST_DIR/vulnerabilities.log"
grep -qx 'Reboot required: YES' "$TEST_DIR/vulnerabilities.log"
check_run verbose 2 --verbose
grep -qx 'Full Grype CVE table' "$TEST_DIR/verbose.log"
grep -qx 'Scanner warning: test diagnostic' "$TEST_DIR/verbose.log"
export GRYPE_STATUS=1
check_run scanner-failure 1
grep -qx 'Scanner error: database failure' "$TEST_DIR/scanner-failure.log"
grep -qx 'Grype scan failed (exit 1).' "$TEST_DIR/scanner-failure.log"
unset GRYPE_STATUS REBOOT
export GRYPE_BAD_JSON=1
check_run invalid-report 5
unset GRYPE_BAD_JSON
export SSH_FAILURE=1
check_run ssh-failure 255
unset SSH_FAILURE
sed 's/install ok installed/install ok unpacked/' "$PACKAGE_DIR/test/fixtures/status" > "$TEST_DIR/source/var/lib/dpkg/status"
tar -cf "$TEST_DIR/inventory.tar" -C "$TEST_DIR/source" etc/os-release var/lib/dpkg/status
check_run incomplete-dpkg 1

# Isolate reboot markers from the test host's /run and /var/run.
sed -e "s|/var/run/reboot-required|$TEST_DIR/legacy-marker|g" \
    -e "s|/run/reboot-required|$TEST_DIR/current-marker|g" \
    "$PACKAGE_DIR/check-restarts.sh" > "$TEST_DIR/check-restarts.sh"
cat > "$TEST_DIR/bin/id" <<'SH'
#!/bin/sh
echo "${REMOTE_UID:-0}"
SH
cat > "$TEST_DIR/bin/needrestart" <<'SH'
#!/bin/sh
set -eu
echo needrestart >> "$TEST_DIR/privileged-calls"
[ "${REMOTE_UID:-0}" = 0 ]
[ "$*" = '-b -r l' ]
if [ "${NEEDRESTART_FAILURE:-0}" = 1 ]; then exit 1; fi
printf 'NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: %s\nNEEDRESTART-UCSTA: %s\nNEEDRESTART-SVC: nginx.service\n' "$KERNEL_STATUS" "$MICROCODE_STATUS"
SH
cat > "$TEST_DIR/bin/sudo" <<'SH'
#!/bin/sh
set -eu
echo sudo >> "$TEST_DIR/privileged-calls"
[ "$*" = '-n needrestart -b -r l' ]
shift
REMOTE_UID=0 exec "$@"
SH
chmod +x "$TEST_DIR/bin/id" "$TEST_DIR/bin/needrestart" "$TEST_DIR/bin/sudo"

export REMOTE_UID=1000 KERNEL_STATUS=1 MICROCODE_STATUS=1
sh "$TEST_DIR/check-restarts.sh" > "$TEST_DIR/restarts.txt"
grep -qx 'Reboot required: NO' "$TEST_DIR/restarts.txt"
grep -qx 'Reboot-required marker is absent.' "$TEST_DIR/restarts.txt"
if grep -Eq 'UNKNOWN|sudo' "$TEST_DIR/restarts.txt"; then exit 1; fi
sh "$TEST_DIR/check-restarts.sh" 0 1 > "$TEST_DIR/restarts-verbose.txt"
grep -qx 'Reboot required: NO' "$TEST_DIR/restarts-verbose.txt"
grep -q '^Additional needrestart checks skipped:' "$TEST_DIR/restarts-verbose.txt"
for marker in current-marker legacy-marker; do
    touch "$TEST_DIR/$marker"
    printf 'linux-image-7.0.0-38-generic\nlinux-base\n' > "$TEST_DIR/$marker.pkgs"
    sh "$TEST_DIR/check-restarts.sh" > "$TEST_DIR/restarts.txt"
    grep -qx 'Reboot required: YES' "$TEST_DIR/restarts.txt"
    grep -qx 'Packages requesting reboot:' "$TEST_DIR/restarts.txt"
    grep -qx 'linux-image-7.0.0-38-generic' "$TEST_DIR/restarts.txt"
    grep -qx 'linux-base' "$TEST_DIR/restarts.txt"
    rm "$TEST_DIR/$marker" "$TEST_DIR/$marker.pkgs"
done
[[ ! -e "$TEST_DIR/privileged-calls" ]]
echo 'PASS unprivileged reboot markers present/absent; no sudo or needrestart calls'

export KERNEL_STATUS=3
sh "$TEST_DIR/check-restarts.sh" 1 | grep -qx 'Reboot required: YES'
grep -qx sudo "$TEST_DIR/privileged-calls"
grep -qx needrestart "$TEST_DIR/privileged-calls"
unset REMOTE_UID

# Exercise the optional checks with controlled needrestart output.
export KERNEL_STATUS=3 MICROCODE_STATUS=1
sh "$TEST_DIR/check-restarts.sh" > "$TEST_DIR/restarts.txt"
grep -qx 'Reboot required: YES' "$TEST_DIR/restarts.txt"
grep -qx 'Restart service: nginx.service' "$TEST_DIR/restarts.txt"
sh "$TEST_DIR/check-restarts.sh" 0 1 > "$TEST_DIR/restarts-verbose.txt"
grep -qx 'NEEDRESTART-SVC: nginx.service' "$TEST_DIR/restarts-verbose.txt"
export KERNEL_STATUS=1 MICROCODE_STATUS=2
sh "$TEST_DIR/check-restarts.sh" | grep -qx 'Reboot required: YES'
export MICROCODE_STATUS=1
sh "$TEST_DIR/check-restarts.sh" | grep -qx 'Reboot required: NO'
export KERNEL_STATUS=0
sh "$TEST_DIR/check-restarts.sh" | grep -qx 'Reboot required: NO'
touch "$TEST_DIR/current-marker"
sh "$TEST_DIR/check-restarts.sh" | grep -qx 'Reboot required: YES'
export KERNEL_STATUS=1
sh "$TEST_DIR/check-restarts.sh" | grep -qx 'Reboot required: YES'
export NEEDRESTART_FAILURE=1
if sh "$TEST_DIR/check-restarts.sh" >/dev/null; then echo 'needrestart failure was swallowed' >&2; exit 1; fi
echo 'PASS optional sudo, kernel, microcode and service checks; markers preserved and failures propagate'
