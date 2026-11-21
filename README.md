# server-audit

Scan installed Debian/Ubuntu packages with Grype over SSH and check for required
reboots. Read-only: nothing is installed, updated or restarted on the server.

[Docker Hub](https://hub.docker.com/r/cubesystems/server-audit)

## Usage

GitLab CI:

```yaml
server audit:
  stage: test
  image: cubesystems/server-audit:1.0@sha256:fb443c65209cb87f08824f7855c1f8cfded025384b5a60e560caea56dc3e3af2
  before_script: []
  script:
    - /usr/local/bin/server-audit
```

Set `AUDIT_HOST`, `AUDIT_USER`, `AUDIT_SSH_PRIVATE_KEY` and
`AUDIT_SSH_KNOWN_HOSTS` as CI variables. Their `DEPLOY_*` equivalents also work.
Run from the project's checkout to use its `.grype.yaml` ignore rules.

## Configuration

| Variable | Default |
| --- | --- |
| `AUDIT_GRYPE` | `grype` |
| `AUDIT_GRYPE_CONFIG` | Project `.grype.yaml`, otherwise no ignore rules; global config is not loaded |
| `AUDIT_FAIL_ON` | `high` |
| `AUDIT_FAIL_ON_REBOOT` | `1`; set `0` to report without failing; `--fail-on-reboot` enables it |
| `AUDIT_NEEDRESTART_SUDO` | `0`; `--needrestart-sudo` runs needrestart via `sudo -n` |
| `AUDIT_VERBOSE` | `0`; `--verbose` shows CVEs, ignored findings, excluded packages and restart details |

SSH also accepts `AUDIT_SSH_PORT`, `AUDIT_SSH_PRIVATE_KEY_PATH`,
`AUDIT_SSH_PRIVATE_KEY_BASE64` and `AUDIT_SSH_KNOWN_HOSTS_PATH`, with corresponding
`DEPLOY_*` fallbacks. Choose one key source and one known-hosts source; otherwise
normal SSH configuration applies. Host-key verification is required.

## Results

- Findings are grouped by package; inactive versioned kernel images/modules are excluded.
- Exit `2`: non-ignored findings at or above the severity threshold, including those without fixes.
- Exit `3`: reboot required, unless disabled. Exit `2` takes precedence.
- Scanner, SSH and collection errors fail the audit.

`needrestart` runs in list-only mode with root access; otherwise reboot checks
use marker files only. Application dependencies and containers are outside scope.

## Development

Requires Bash, SSH, tar, realpath, jq and Grype:

```sh
AUDIT_HOST=server.example.com AUDIT_USER=audit bash ./server-audit.sh
bash test/smoke.sh
```

Tests use local command doubles and never connect to a server.
