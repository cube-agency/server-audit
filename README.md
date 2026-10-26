# server-audit

A shell-based server audit tool distributed as a Docker image.
`server-audit.sh` collects remote Debian/Ubuntu package metadata over SSH and runs
Grype locally. `check-restarts.sh` checks reboot markers and runs `needrestart` in
list-only mode. Nothing is installed, updated or restarted on the server.

## Usage

Use the image pinned by version and digest. For GitLab CI:

```yaml
server audit:
  stage: test
  image: cubesystems/server-audit:1.0@sha256:fb443c65209cb87f08824f7855c1f8cfded025384b5a60e560caea56dc3e3af2
  before_script: []
  script:
    - /usr/local/bin/server-audit
```

Pass `AUDIT_HOST`, `AUDIT_USER`, `AUDIT_SSH_KNOWN_HOSTS` and
`AUDIT_SSH_PRIVATE_KEY` through CI variables. The image includes the audit scripts,
Grype and the required tools. Run from the application's checkout so its
`.grype.yaml` applies. Nonzero audit exits should fail the job.

The digest pins the scripts and installed tools; Grype still refreshes its
vulnerability database. The remote server needs `sh`, tar and a Debian/Ubuntu
dpkg database.

## Configuration

| Variable | Default |
| --- | --- |
| `AUDIT_HOST`, `AUDIT_USER` | Corresponding `DEPLOY_HOST`, `DEPLOY_USER`; required |
| `AUDIT_SSH_PORT` | `DEPLOY_SSH_PORT`, otherwise SSH config |
| `AUDIT_SSH_PRIVATE_KEY_PATH` | `DEPLOY_SSH_PRIVATE_KEY_PATH`, otherwise normal SSH keys/agent |
| `AUDIT_SSH_PRIVATE_KEY` | `DEPLOY_SSH_PRIVATE_KEY`; inline CI key |
| `AUDIT_SSH_PRIVATE_KEY_BASE64` | `DEPLOY_SSH_PRIVATE_KEY_BASE64`; base64 CI key |
| `AUDIT_SSH_KNOWN_HOSTS_PATH` | `DEPLOY_SSH_KNOWN_HOSTS_PATH`, otherwise normal SSH known_hosts |
| `AUDIT_SSH_KNOWN_HOSTS` | `DEPLOY_SSH_KNOWN_HOSTS`; inline trusted host entries |
| `AUDIT_GRYPE` | `grype` executable |
| `AUDIT_GRYPE_CONFIG` | `.grype.yaml` in the working directory, otherwise temporary `ignore: []`; global config files are not loaded |
| `AUDIT_FAIL_ON` | `high` |
| `AUDIT_NEEDRESTART_SUDO` | `0`; `--needrestart-sudo` sets it to `1` |
| `AUDIT_FAIL_ON_REBOOT` | `0`; `--fail-on-reboot` sets it to `1` |
| `AUDIT_VERBOSE` | `0`; `--verbose` prints the full Grype CVE table, including ignored matches, and needrestart evidence |

Choose one key source and one known-hosts source. Inline credentials use private
temporary files with cleanup traps. Existing SSH files are not overwritten and
host-key verification stays enabled. Grype's `GRYPE_*` settings still apply.

## Ignore rules

Use Grype's native `.grype.yaml` rules. Each rule can match a
package, version, CVE or source package and records a reason. Set
`AUDIT_GRYPE_CONFIG` to use a different file; an explicitly missing file fails.
No built-in exclusions are applied.

Ignored matches do not fail the audit. All other High/Critical matches still
exit `2`, including findings without fixes. Ignored counts are shown in the
summary and individual matches are available with `--verbose`. Review exceptions
when the server's packages or usage change. To check without exceptions, use a
config containing `ignore: []`.

## Results

The default report groups advisories by package and installed version:

- Packages with published fix versions, across all severities.
- Packages with findings at or above `AUDIT_FAIL_ON` that have no published fix.
- Counts of other findings, total matches and ignored matches.

Grype's progress display and logs stream live during the scan. `--verbose` also
prints the full CVE table. The progress severity totals may include ignored
findings; the summary and exit code use only non-ignored matches. Scanner errors
always print their diagnostic output and fail the command. Restart status is
reported separately from vulnerability findings.

Each group shows at most ten packages. Repeated CVEs for the same package/version
are counted once. Versioned kernel images/modules are marked as running or not
running; findings not explicitly ignored participate in Grype's failure threshold. Findings
without affected-version bounds are marked for applicability review. Published
fix versions come from Grype; availability in the server's APT repositories is
not checked. The summary does not confirm exploitability or validate third-party
packages against their vendors' advisories.

Restart output includes the running kernel, reboot marker/packages, services
needing restart, and `Reboot required: YES/NO/UNKNOWN`. `--verbose` includes the
raw needrestart evidence.

Collected metadata, Grype JSON and restart data use a fresh temporary directory for each
run, automatically removed on completion or failure. Repeated runs need no
manual cleanup or output-directory configuration. No report files are created
in the project.

The temporary dpkg snapshot preserves architectures, epochs and source-package
versions. Removed packages are omitted; incomplete dpkg transactions fail the audit.

`needrestart` needs root visibility. For another account, `--needrestart-sudo`
uses `sudo -n needrestart -b -r l` if already permitted. Missing tools/privileges
are reported; an attempted command that fails stops the audit. Marker absence
alone is insufficient: `NO` requires current kernel and microcode checks;
otherwise the result is `UNKNOWN`. No services are restarted.

Exit `2` means a non-ignored finding exceeded Grype's severity threshold, including
findings without fixes or affected-version bounds. Exit `3` means a reboot
is required and `--fail-on-reboot` was enabled; vulnerability exit `2` takes
precedence. Other command failures remain nonzero. Unknown restart status does
not trigger exit `3`.

This scans installed OS packages, not application dependencies, containers or
manually installed binaries. A removed but still running kernel is outside the
package inventory; its running version and restart status are reported separately.

## Development

To run from a checkout, install Bash, SSH, tar, realpath, jq and Grype locally:

```sh
AUDIT_HOST=server.example.com AUDIT_USER=audit bash ./server-audit.sh
```

Run `bash test/smoke.sh` for shell smoke tests.
The tests use local command doubles and never connect to a server.

References: [Grype scan targets](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/),
[needrestart batch mode](https://github.com/liske/needrestart/blob/master/README.batch.md).
