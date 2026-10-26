#!/usr/bin/env bash
set -euo pipefail
umask 077

AUDIT_SCRIPT=$(realpath "${BASH_SOURCE[0]}")
AUDIT_DIR=$(dirname "$AUDIT_SCRIPT")
AUDIT_HOST=${AUDIT_HOST:-${DEPLOY_HOST:-}}
AUDIT_USER=${AUDIT_USER:-${DEPLOY_USER:-}}
AUDIT_GRYPE=${AUDIT_GRYPE:-grype}
AUDIT_FAIL_ON=${AUDIT_FAIL_ON:-high}
AUDIT_FAIL_ON_REBOOT=${AUDIT_FAIL_ON_REBOOT:-0}
AUDIT_NEEDRESTART_SUDO=${AUDIT_NEEDRESTART_SUDO:-0}
AUDIT_VERBOSE=${AUDIT_VERBOSE:-0}

for argument in "$@"; do
    case "$argument" in
        --needrestart-sudo) AUDIT_NEEDRESTART_SUDO=1 ;;
        --fail-on-reboot) AUDIT_FAIL_ON_REBOOT=1 ;;
        --verbose) AUDIT_VERBOSE=1 ;;
        --help)
            echo 'Usage: AUDIT_HOST=host AUDIT_USER=user server-audit [--needrestart-sudo] [--fail-on-reboot] [--verbose]'
            echo 'Uses AUDIT_SSH_* or DEPLOY_SSH_* settings. See README.md for configuration.'
            exit 0 ;;
        *) echo "Unknown option: $argument" >&2; exit 1 ;;
    esac
done
: "${AUDIT_HOST:?Set AUDIT_HOST or DEPLOY_HOST}"
: "${AUDIT_USER:?Set AUDIT_USER or DEPLOY_USER}"
case "$AUDIT_FAIL_ON" in negligible|low|medium|high|critical) ;; *) echo 'Invalid AUDIT_FAIL_ON' >&2; exit 1 ;; esac
case "$AUDIT_NEEDRESTART_SUDO:$AUDIT_FAIL_ON_REBOOT" in 0:0|0:1|1:0|1:1) ;; *) echo 'Boolean settings must be 0 or 1' >&2; exit 1 ;; esac
case "$AUDIT_VERBOSE" in 0|1) ;; *) echo 'AUDIT_VERBOSE must be 0 or 1' >&2; exit 1 ;; esac
jq --version >/dev/null
"$AUDIT_GRYPE" version >/dev/null

AUDIT_TEMP=$(mktemp -d "${TMPDIR:-/tmp}/server-audit.XXXXXX")
trap 'rm -rf "$AUDIT_TEMP"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Use the project's explicit exceptions, without loading a user's global config.
grype_config=${AUDIT_GRYPE_CONFIG:-}
if [[ -z "$grype_config" && -f .grype.yaml ]]; then grype_config=.grype.yaml; fi
if [[ -z "$grype_config" ]]; then
    grype_config="$AUDIT_TEMP/grype.yaml"
    printf 'ignore: []\n' > "$grype_config"
elif [[ ! -f "$grype_config" || ! -r "$grype_config" ]]; then
    echo "Cannot read Grype config: $grype_config" >&2
    exit 1
else
    echo "Grype config: $grype_config"
fi

# Keep CI credentials separate from the user's existing SSH files.
key_path=${AUDIT_SSH_PRIVATE_KEY_PATH:-${DEPLOY_SSH_PRIVATE_KEY_PATH:-}}
key=${AUDIT_SSH_PRIVATE_KEY:-${DEPLOY_SSH_PRIVATE_KEY:-}}
key_base64=${AUDIT_SSH_PRIVATE_KEY_BASE64:-${DEPLOY_SSH_PRIVATE_KEY_BASE64:-}}
if [[ -n "$key" && -n "$key_base64" ]] || [[ -n "$key_path" && -n "$key$key_base64" ]]; then
    echo 'Set only one SSH key path, inline key or base64 key' >&2
    exit 1
fi
if [[ -n "$key$key_base64" ]]; then
    key_path="$AUDIT_TEMP/identity"
    if [[ -n "$key" ]]; then printf '%s\n' "$key" > "$key_path";
    else printf '%s' "$key_base64" | base64 -d > "$key_path"; fi
fi
unset key key_base64 AUDIT_SSH_PRIVATE_KEY DEPLOY_SSH_PRIVATE_KEY AUDIT_SSH_PRIVATE_KEY_BASE64 DEPLOY_SSH_PRIVATE_KEY_BASE64
known_hosts_path=${AUDIT_SSH_KNOWN_HOSTS_PATH:-${DEPLOY_SSH_KNOWN_HOSTS_PATH:-}}
known_hosts=${AUDIT_SSH_KNOWN_HOSTS:-${DEPLOY_SSH_KNOWN_HOSTS:-}}
if [[ -n "$known_hosts_path" && -n "$known_hosts" ]]; then
    echo 'Set only one known_hosts path or inline value' >&2
    exit 1
fi
if [[ -n "$known_hosts" ]]; then
    known_hosts_path="$AUDIT_TEMP/known_hosts"
    printf '%s\n' "$known_hosts" > "$known_hosts_path"
fi
SSH_ARGS=(-T -o BatchMode=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no
    -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=2
    -o ForwardAgent=no -o ClearAllForwardings=yes -l "$AUDIT_USER")
if [[ -n "$key_path" ]]; then SSH_ARGS+=(-i "$key_path" -o IdentitiesOnly=yes); fi
if [[ -n "$known_hosts_path" ]]; then SSH_ARGS+=(-o "UserKnownHostsFile=\"$known_hosts_path\""); fi
port=${AUDIT_SSH_PORT:-${DEPLOY_SSH_PORT:-}}
if [[ -n "$port" ]]; then SSH_ARGS+=(-p "$port"); fi

# Collected metadata belongs to this run and is removed by the EXIT trap.
snapshot="$AUDIT_TEMP/snapshot"
mkdir -p "$snapshot/etc" "$snapshot/var/lib/dpkg"
echo "Collecting OS packages from $AUDIT_USER@$AUDIT_HOST..."
ssh "${SSH_ARGS[@]}" -- "$AUDIT_HOST" 'tar -chf - -C / etc/os-release var/lib/dpkg/status' > "$AUDIT_TEMP/inventory.tar"
# Read only the two expected archive members; do not extract remote paths.
tar -xOf "$AUDIT_TEMP/inventory.tar" etc/os-release > "$snapshot/etc/os-release"
os_id=$(sed -n 's/^ID=//p' "$snapshot/etc/os-release" | tr -d "\"'")
os_version=$(sed -n 's/^VERSION_ID=//p' "$snapshot/etc/os-release" | tr -d "\"'")
case "$os_id" in debian|ubuntu) ;; *) echo "Unsupported OS: $os_id" >&2; exit 1 ;; esac
if [[ ! "$os_version" =~ ^[0-9]+([.][0-9]+)*$ ]]; then echo 'Missing or unsupported OS version' >&2; exit 1; fi
tar -xOf "$AUDIT_TEMP/inventory.tar" var/lib/dpkg/status | awk '
    BEGIN { RS=""; FS="\n"; ORS="\n\n" }
    {
        status=""
        for (i=1; i<=NF; i++) if ($i ~ /^Status: /) status=$i
        if (status ~ /^Status: [^ ]+ ok installed$/) { print; count++ }
        else if (status !~ /^Status: [^ ]+ [^ ]+ (not-installed|config-files)$/) {
            print "Incomplete or invalid dpkg state: " status > "/dev/stderr"; exit 1
        }
    }
    END { if (!count) { print "No installed packages collected" > "/dev/stderr"; exit 1 } }
' > "$snapshot/var/lib/dpkg/status"
printf '%s %s: %s installed packages\n' "$os_id" "$os_version" "$(grep -c '^Package: ' "$snapshot/var/lib/dpkg/status")"

ssh "${SSH_ARGS[@]}" -- "$AUDIT_HOST" sh -s -- "$AUDIT_NEEDRESTART_SUDO" "$AUDIT_VERBOSE" < "$AUDIT_DIR/check-restarts.sh" > "$AUDIT_TEMP/restarts.txt"
cat "$AUDIT_TEMP/restarts.txt"
running_kernel=$(sed -n 's/^Running kernel: //p' "$AUDIT_TEMP/restarts.txt")

# Native ignore rules apply to both the report and Grype's severity threshold.
grype_output=(--output "json=$AUDIT_TEMP/grype.json")
if [[ "$AUDIT_VERBOSE" = 1 ]]; then grype_output+=(--output table --show-suppressed); fi
scan_status=0
echo 'Scanning for vulnerabilities...'
"$AUDIT_GRYPE" "dir:$snapshot" --name "$AUDIT_HOST" --config "$grype_config" --fail-on "$AUDIT_FAIL_ON" \
    "${grype_output[@]}" || scan_status=$?
case "$scan_status" in
    0|2) ;;
    *) echo "Grype scan failed (exit $scan_status)." >&2; exit "$scan_status" ;;
esac
jq -r --arg threshold "$AUDIT_FAIL_ON" --arg kernel "$running_kernel" -f "$AUDIT_DIR/summary.jq" "$AUDIT_TEMP/grype.json"
if [[ "$scan_status" = 2 ]]; then echo "Threshold exceeded: $AUDIT_FAIL_ON or higher (including findings without fixes)."; fi
if [[ "$scan_status" = 0 && "$AUDIT_FAIL_ON_REBOOT" = 1 ]] && grep -qx 'Reboot required: YES' "$AUDIT_TEMP/restarts.txt"; then exit 3; fi
exit "$scan_status"
