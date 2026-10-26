# server-audit

A shell-based npm package proof of concept, following shell-deployer's pattern.
`server-audit.sh` collects remote Debian/Ubuntu package metadata over SSH and runs
Grype locally. `check-restarts.sh` checks reboot markers and runs `needrestart` in
list-only mode. Nothing is installed, updated or restarted on the server.

## Usage

Requires Bash, SSH, tar, realpath, jq and Grype locally; the server needs `sh`, tar
and a Debian/Ubuntu dpkg database. npm distributes the scripts; there is no
JavaScript runtime code or npm dependency. Tested with Grype 0.121.0.

From a checkout of this repository:

```sh
AUDIT_HOST=server.example.com AUDIT_USER=audit bash ./server-audit.sh
```

Once the repository is pushed to GitHub, run it from your project's directory
so its `.grype.yaml` is used (Git is also required):

```sh
AUDIT_HOST=server.example.com AUDIT_USER=audit \
  npx --yes --package github:cube-agency/server-audit server-audit
```

Existing SSH keys/agent and trusted host entries work normally. After npm
publication, the intended command is
`npx --yes --package server-audit@<version> server-audit`. This package is unpublished.

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
The npm package has no built-in exclusions.

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

## CI and verification

On a runner with the required shell tools, Grype, Node.js, npm and Git, pass
`AUDIT_HOST`, `AUDIT_USER`, `AUDIT_SSH_KNOWN_HOSTS` and `AUDIT_SSH_PRIVATE_KEY`
through CI variables, then run:

```sh
npx --yes --package github:cube-agency/server-audit server-audit
```

Run from the application's checkout so its `.grype.yaml` applies. Nonzero audit
exits should fail the job. The GitHub command uses the repository's default branch;
append `#<commit>` to the package source to pin a revision once one is published.

Run `npm test` for shell smoke tests, or `npm pack --dry-run` to inspect the package.
The tests use local command doubles and never connect to a server.

References: [Grype scan targets](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/),
[needrestart batch mode](https://github.com/liske/needrestart/blob/master/README.batch.md).
