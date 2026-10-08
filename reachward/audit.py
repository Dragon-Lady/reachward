from collections import defaultdict
from datetime import datetime, timezone
import os
import subprocess

from .collectors import scopes
from .safety import SafeError

RULES = {
    "RW-INLINE-SECRET", "RW-FILE-MODE", "RW-BROAD-SCOPE", "RW-STALE",
    "RW-UNKNOWN-SERVER", "RW-SERVER-CHANGED", "RW-UNPINNED-LAUNCH", "RW-DUP-CREDENTIAL", "RW-KEY-FILE-REFERENCE",
}
BROAD = {"repo", "admin:org", "delete_repo", "workflow", "admin:repo_hook", "write:packages",
         "https://mail.google.com/", "https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/gmail.modify"}


def online_scopes(inventory):
    """The only audit subprocess: opt-in, no tokens requested, no response logged."""
    try:
        result = subprocess.run(["gh", "api", "-i", "/user"], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=5, check=False,
                                env=dict(os.environ, PATH=inventory.command_path))
    except (OSError, subprocess.SubprocessError):
        raise SafeError("optional GitHub scope check failed") from None
    if result.returncode != 0:
        raise SafeError("optional GitHub scope check failed")
    # Body and unrelated headers are never parsed or persisted.
    header = result.stdout.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    found = None
    for line in header.splitlines():
        name, sep, value = line.partition(b":")
        if sep and name.strip().lower() == b"x-oauth-scopes":
            found = scopes(value.decode("ascii", errors="ignore").strip())
    host = os.environ.get("GH_HOST", "github.com")
    matching = [e for e in inventory.entries if e["collector"] == "gh" and e.get("host") == host]
    for entry in matching:
        entry["scope_visibility"] = "online CLI identity (may use environment override); header absent" if found is None else "online CLI identity (may use environment override)"
        entry["scopes"] = found or []
    inventory.online = {"host": host, "scopes": found or [], "header_present": found is not None,
                        "matched_config": bool(matching)}


def apply_rules(inventory):
    duplicates = defaultdict(list)
    for entry in inventory.entries:
        add = lambda rule, reason, severity="warn": inventory.finding(rule, entry, reason, severity)
        if entry.get("inline_secret"):
            add("RW-INLINE-SECRET", "Credential written inline in MCP configuration or arguments", "high")
        if entry.get("key_file_references"):
            add("RW-KEY-FILE-REFERENCE", "Credential file reference recorded; target contents, existence and permissions not inspected", "info")
        credential_file = bool(entry["credentials"]) or entry["kind"] == "credential"
        if credential_file and (int(entry["mode"], 8) & 0o177 or int(entry["directory_mode"], 8) & 0o077):
            add("RW-FILE-MODE", "Credential file permits access beyond 0600 or its directory beyond 0700", "high")
        broad = bool(set(entry["scopes"]) & BROAD) or (entry.get("remote_type") == "drive" and "drive" in entry["scopes"])
        if broad:
            add("RW-BROAD-SCOPE", "Broad scope visible or manually declared")
        elif entry.get("remote_type") == "onedrive" and entry.get("drive_type"):
            add("RW-BROAD-SCOPE", "OneDrive drive type recorded; effective permissions not verified", "info")
        reasons = []
        if credential_file and inventory.now.timestamp() - entry["mtime_ns"] / 1e9 > inventory.cfg.get("stale_days", 90) * 86400:
            reasons.append("Credential file metadata older than configured threshold; token age is not proven")
        if entry.get("expiry"):
            expiry = datetime.fromisoformat(entry["expiry"])
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if (inventory.now - expiry).total_seconds() > 30 * 86400:
                reasons.append("Recorded rclone token expiry is more than 30 days past")
        if entry["kind"] == "manual" and (not entry.get("review_by") or entry["review_by"] < inventory.now.date().isoformat()):
            reasons.append("Manual connector review missing or overdue")
        if entry.get("command_missing"):
            reasons.append("MCP launch command missing or not executable using configured command search path")
        if reasons:
            add("RW-STALE", "; ".join(reasons))
        if entry["kind"] == "mcp" and not entry.get("known"):
            add("RW-UNKNOWN-SERVER", "MCP server name is not in known_servers")
        if entry.get("launch_unpinned"):
            add("RW-UNPINNED-LAUNCH", "Package runner lacks an exact version pin", "info")
        for fp in entry["credentials"]:
            duplicates[fp].append(entry)
    for fp, entries in duplicates.items():
        if len(entries) > 1:
            for entry in entries:
                inventory.finding("RW-DUP-CREDENTIAL", entry, "Credential " + fp + " occurs in multiple inventory entries", "info")


def changes(current, baseline):
    # Skipped sources cannot prove either removal or addition. Source identities
    # remain stable even when display paths are redacted. The path fallback also
    # supports baselines created before source IDs were introduced.
    skipped = [s for value in (current, baseline) for s in value.get("sources", [])
               if s.get("coverage") == "warning" or s.get("status") == "encrypted: not inspected"]
    skipped_ids = {s.get("source_id") for s in skipped} - {None}
    skipped_paths = {(s["collector"], s["path"]) for s in skipped}
    current["comparison_warnings"] = [
        {"source_id": sid, "reason": "Source not inspected on both sides; related entries excluded from comparison"}
        for sid in sorted(skipped_ids)
    ]
    uncertain_env_sets = []
    for value in (current, baseline):
        sources = value.get("sources", [])
        if any(s.get("coverage") == "warning" and s["collector"] in {"cursor", "codex", "claude", "vscode", "other"} for s in sources):
            uncertain_env_sets.append({(s["collector"], s["path"]) for s in sources})
    def comparable(entry):
        source = (entry["collector"], entry["source"])
        if entry.get("source_id") in skipped_ids or source in skipped_paths:
            return False
        # A skipped MCP file can conceal its env-file references. Conservatively
        # withhold removals for env sources no longer enumerated in this scan.
        return not (entry["collector"] == "env" and any(source not in seen for seen in uncertain_env_sets))
    old = {e["id"]: e for e in baseline["entries"] if comparable(e)}
    new = {e["id"]: e for e in current["entries"] if comparable(e)}
    result = []
    for eid in sorted(set(old) | set(new)):
        if eid not in old:
            result.append({"change": "added", "entry": eid, "name": new[eid]["name"], "fields": []})
        elif eid not in new:
            result.append({"change": "removed", "entry": eid, "name": old[eid]["name"], "fields": []})
        else:
            derived = {"mtime_ns", "known", "command_missing", "source_id"}
            if new[eid]["collector"] == "gh":
                derived |= {"scopes", "scope_visibility"}  # Optional online observation only.
            fields = sorted(k for k in set(old[eid]) | set(new[eid]) if k not in derived and old[eid].get(k) != new[eid].get(k))
            if fields:
                result.append({"change": "changed", "entry": eid, "name": new[eid]["name"], "fields": fields})
                if new[eid].get("known") and set(fields) & {"command_hmac", "args_hmac", "url_host", "transport"}:
                    current["findings"].append({"rule": "RW-SERVER-CHANGED", "severity": "high", "entry": eid,
                                               "reason": "Known server launch or destination changed against baseline"})
    return result


def snapshot(inventory, baseline=None, include_diff=False):
    apply_rules(inventory)
    problems = [s for s in inventory.sources if s["coverage"] == "error"]
    warnings = [{"source_id": s["source_id"], "reason": s["status"]} for s in inventory.sources if s["coverage"] == "warning"]
    if getattr(inventory, "home_alias", False):
        warnings.append({"reason": "HOME alias resolved; no-follow checks apply below the canonical home"})
    coverage = "error" if problems else "partial" if warnings else "complete"
    value = {"schema": 1, "time": inventory.now.isoformat(), "complete": coverage == "complete",
             "coverage": coverage, "coverage_warnings": warnings, "baseline_eligible": not problems,
             "entries": inventory.entries, "sources": inventory.sources, "findings": inventory.findings,
             "changes": [], "comparison_warnings": []}
    if hasattr(inventory, "online"):
        value["online"] = inventory.online
    value = inventory.redactor.clean(value)
    if baseline:
        if not value["baseline_eligible"]:
            if include_diff:
                raise SafeError("incomplete inventory; comparison refused (run list-sources)")
        else:
            diff = changes(value, baseline)
            if include_diff:
                value["changes"] = diff
    elif include_diff:
        raise SafeError("no baseline; inspect a scan then run baseline")
    return inventory.redactor.clean(value)
