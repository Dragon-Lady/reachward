# Reach Ward

Reach Ward inventories local agent and MCP configurations, credential fingerprints,
and visible or manually declared scopes. It reports risky settings and changes
against a baseline. It is an advisory auditor, not an access-control boundary.

Built and maintained by Dragon Lady — [GitHub](https://github.com/Dragon-Lady).

## Posture

- Linux first, Python 3.10 or newer. Apache-2.0.
- Offline by default. No telemetry, server execution, config edits, token rotation,
  browser-cookie access, or SQLite database access.
- No secret values, full arguments, file contents, or conversation history saved.
  Credentials are represented by `fp:` and 16 hexadecimal characters from
  HMAC-SHA256 with a private, random, per-installation 32-byte key.
- Local reports and state contain source paths, server and variable names,
  command basenames, URL hosts, credential fingerprints, scopes, file metadata,
  and the configured GitHub username. Treat these reports as private metadata.
- Only Reach Ward's state and explicitly requested reports are written. Targets
  are opened read-only; original bytes, modes, size, and mtime are preserved.
- State directory: 0700. New state/report files: 0600 from creation. Unsafe
  existing state modes are refused, never repaired with chmod. Report output is
  create-only and never overwrites an existing file.
- No claim that a host, credential, package, server, or account is safe. A
  credential's existence does not prove it is valid or accessible to an agent.

## Install from source

This version is awaiting independent review. A PyPI release is not yet published.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/reachward --help
.venv/bin/reachward list-sources
.venv/bin/reachward scan
```

Runtime uses the standard library, plus `tomli` on Python 3.10 only. Building
requires setuptools; developing/tests require pytest. No package installs occur
during a scan.

## Commands

```sh
reachward scan --format json
reachward scan --roots ~/projects/example
reachward baseline                  # after locally reviewing the inventory
reachward diff                      # exit 0 if unchanged, 1 for changes
reachward scan --diff --format html --output reachward-report.html
reachward known add example-server
reachward known list
reachward known remove example-server
reachward list-sources
reachward report --since 7d
reachward report --send             # aggregate alert; stdout unless configured
reachward print-timer --interval 1h # prints only; does not install or enable
```

Every command supports `--format text|json|md|html` and `--output FILE`. HTML is
self-contained and escaped; no scripts, remote assets, or executable links.
An existing baseline requires `baseline --force` to replace it. Establishing a
baseline does not approve findings or add names to the known-server list.

Exit codes: **0** no findings (or no changes for `diff`); **1** findings/changes;
**2** usage, incomplete scan, unsafe file modes, or runtime/delivery error.
An incomplete scan cannot replace a baseline or produce a misleading diff.
Encrypted rclone sources are explicitly marked uninspected rather than errors.
Missing optional default files are normal; explicit extra sources/env files are
required. Removing a previously inventoried optional source produces removals.

Metadata mtime alone is not an inventory change, preventing unrelated file edits
from flagging every server. Credential, mode, command, argument, destination and
other inventory changes are compared. Baselines and fingerprints are local to
their key: do not compare baselines from different machines or regenerate a key
in place. Preserve `fp.key` with backups of the state.

## Sources

| Collector | Sources |
|---|---|
| Cursor | `~/.cursor/mcp.json`, root `.cursor/mcp.json` |
| Codex | `~/.codex/config.toml`, `~/.codex/auth.json` |
| Claude | `~/.claude.json` including project maps, root `.mcp.json`, XDG `Claude/claude_desktop_config.json` |
| VS Code | XDG `Code/User/mcp.json`, root `.vscode/mcp.json`; JSONC accepted |
| Other | `~/.codeium/windsurf/mcp_config.json`, `~/.gemini/settings.json`, configured extra paths |
| GitHub CLI | XDG `gh/hosts.yml`, or `GH_CONFIG_DIR/hosts.yml` |
| rclone | XDG `rclone/rclone.conf`, or `RCLONE_CONFIG` |
| Environment | Explicit `env_files`, MCP `envFile`/`env_file`/plural fields and `--env-file` arguments |
| Manual | XDG `reachward/cloud_connectors.toml` |

XDG means `$XDG_CONFIG_HOME`, default `~/.config`. Roots are explicit, not
recursively searched. Extra sources must be JSON/JSONC or TOML MCP maps. Relative
env-file references resolve against the MCP config directory; unresolved variable
references are not expanded. General shell syntax and multiline dotenv values
are not interpreted. Encrypted rclone configs never prompt for a password.

All sources must be under `$HOME`. All symlinks (including parent components) are
refused, a conservative restriction that also prevents following them outside
home. Special files, files over 5 MiB, unreadable files and files changing during
a read are not inspected. Checks use no-follow directory/file descriptors.

`hosts.yml` is parsed using a restricted, non-executing subset covering gh's
host/user records; unsupported YAML is an explicit incomplete scan. Absence of
an inline token means **keyring or absent: not inspected**. Reach Ward never
queries the keyring, uses `gh auth token`, or claims a token is present there.

## Findings

| Rule | Meaning |
|---|---|
| `RW-INLINE-SECRET` | Credential inline in an MCP config, header, URL auth/query, or recognized argument |
| `RW-FILE-MODE` | Credential file permits access beyond 0600, or immediate directory beyond 0700 |
| `RW-BROAD-SCOPE` | A listed GitHub/Google full-access scope, rclone Drive `drive`, or informational OneDrive drive type |
| `RW-STALE` | Old file metadata, rclone expiry over 30 days past, overdue manual review, or missing launch executable |
| `RW-UNKNOWN-SERVER` | Server name not in configured or locally managed known names |
| `RW-SERVER-CHANGED` | Known server's command, arguments, host or transport changed against baseline |
| `RW-UNPINNED-LAUNCH` | `npx -y`, `uvx` or `pipx run` without an exact package version; informational |
| `RW-DUP-CREDENTIAL` | Same fingerprint in more than one inventory entry; informational |

Arguments and full commands are compared with keyed HMACs, not stored. The
argument shape uses only generic categories. Pin detection is conservative and
does not resolve packages or wrapper scripts. Scopes inferred from local files
or manual entries are declarations, not proof of actual provider permissions.
File age is not token age. Missing command checks use the current PATH/config
directory; clients with different launch environments may behave differently.

## Configuration and alerts

Config: `~/.config/reachward/config.toml` (0600), or global `--config FILE`.
See [example config](examples/config.toml) and
[manual connectors](examples/cloud_connectors.toml). `known add/remove` updates
only Reach Ward's private `known.json`; it never edits the config. Configured
known names must be removed by explicitly editing the config.

`alert_channels` accepts `stdout`, `slack`, `ntfy`, `email`; `[]` means stdout.
Configuring external channels explicitly enables alert networking. `scan` sends
new high findings and requested baseline changes; `report --send` sends all
current findings/changes. Messages contain only counts, rule IDs and severity,
ending with `run reachward report locally for details` (command in backticks).
No paths, hosts, server names, account identifiers, or fingerprints leave the
machine in alerts. Dedupe lasts 24 hours per rule/entry/channel/destination;
failed deliveries are retried on the next run. Each network operation uses a
5-second timeout; redirects are disabled. HTTPS is required, except on loopback;
SMTP requires TLS off loopback. Environment variable **names** hold references
to Slack webhook, ntfy token and SMTP password. Never inline a Slack webhook.

The optional **`scan --online`** runs exactly `gh api -i /user` and reads only
`X-OAuth-Scopes`. It does not run during normal scans. This uses the active gh CLI
identity, which may be affected by environment overrides; it does not prove
scopes for every saved credential. A missing header means unknown, not no scopes.
No Google/Slack token introspection, MCP connections or other audit networking.

State under `$XDG_STATE_HOME/reachward` (default `~/.local/state/reachward`):
`fp.key`, `baseline.json`, `last.json`, `known.json`, aggregate `history.json`
(30 days, at most 1,000 runs), and HMAC-only `alerts.json` dedupe receipts.
State is bounded to 5 MiB per file. A malicious process already running as the
same user can tamper with configs or local baselines; this tool does not defend
against a compromised user account. Run one writer per state directory.

## Review and tests

```sh
python3 -m pip install pytest
python3 -m pytest -q
```

Tests use a fake HOME and fake XDG directories. Coverage includes every rule,
canaries in every command/format, target preservation, private files from
creation, no-network/no-subprocess offline checks, diff mutations, parse errors,
symlinks, FIFOs, bounded reads, and mocked online/alert paths. No GitHub Actions
workflow is enabled. Timers are templates only; independently review a baseline,
choose an executable path and approve scheduling before installing units.

Collector format references: [VS Code MCP](https://code.visualstudio.com/docs/agent-customization/mcp-servers),
[Claude MCP](https://code.claude.com/docs/en/mcp),
[gh api](https://cli.github.com/manual/gh_api), and [rclone](https://rclone.org/docs/).
