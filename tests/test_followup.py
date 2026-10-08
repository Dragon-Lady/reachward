"""Regressions from the independent retest; all sources live in fake HOME."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from reachward import collectors
from reachward.audit import online_scopes, snapshot
from reachward.cli import main
from reachward.config import command_search_path, locations
from reachward.safety import SafeError, fingerprint, secret_name

KEY = bytes(range(32))
TOKEN = "gh" + "p_" + hashlib.sha256(b"followup fake token").hexdigest()[:36]
OPAQUE = "fixture-only-" + hashlib.sha256(b"not a real credential").hexdigest()


def collect(home, cfg=None):
    return collectors.Inventory(home, home / ".config", cfg or {}, KEY).collect()


def mcp(put, server, path=".cursor/mcp.json", name="demo"):
    return put(path, json.dumps({"mcpServers": {name: server}}))


def rule(value, name):
    return [f for f in value["findings"] if f["rule"] == name]


def run(args, capsys):
    code = main(args + ["--format", "json"])
    output = capsys.readouterr()
    return code, json.loads(output.out) if output.out else None, output.err


def receipt(path):
    info = path.stat()
    return hashlib.sha256(path.read_bytes()).hexdigest(), info.st_size, info.st_mtime_ns, info.st_mode, info.st_ino


@pytest.mark.parametrize("name", ["MAX_TOKENS", "TOKENIZERS_PARALLELISM", "maxTokens", "TOKEN_COUNT",
    "PATH", "NODE_PATH", "PYTHONPATH", "LD_LIBRARY_PATH", "NODE_REPL_TRUSTED_CODE_PATHS",
    "CODEX_CLI_PATH", "NODE_REPL_NODE_PATH", "XDG_DATA_PATHS", "projectPath", "KEYBOARD_LAYOUT",
    "MONKEY", "PATTERN", "DISPATCH_MODE", "LOG_LEVEL"])
def test_semantic_name_negatives(home, put, name):
    assert not secret_name(name)
    source = mcp(put, {"command": sys.executable, "env": {name: str(home)}, name: str(home),
                       "args": ["--" + name, str(home)]}, name=str(home))
    env = put(".env", name + "=" + str(home) + "\n")
    value = snapshot(collect(home, {"env_files": [str(env)]}))
    assert not rule(value, "RW-INLINE-SECRET")
    assert len(value["entries"]) == 1 and value["entries"][0]["credentials"] == []
    assert value["entries"][0]["source"] == str(source)
    assert value["entries"][0]["name"] == str(home)


@pytest.mark.parametrize("name", ["GITHUB_PAT", "MY_PAT", "GH_PAT_TOKEN", "PAT", "githubPat", "GITLAB_PAT",
    "API_KEY", "apiKey", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "SLACK_WEBHOOK", "DB_PASSWORD",
    "API_KEYS", "OPENAI_KEYS", "GITHUBPAT", "accessToken", "credentials", "clientSecret"])
def test_semantic_name_positives(home, put, name):
    assert secret_name(name)
    mcp(put, {"command": sys.executable, "env": {name: OPAQUE}}, name=OPAQUE)
    env = put(".env", name + "=" + OPAQUE + "\n")
    value = snapshot(collect(home, {"env_files": [str(env)]}))
    assert rule(value, "RW-INLINE-SECRET")
    assert len(value["entries"]) == 2
    assert all(e["credentials"] == [fingerprint(KEY, OPAQUE)] for e in value["entries"])
    assert OPAQUE not in json.dumps(value)


def test_plural_key_list_values(home, put):
    mcp(put, {"command": sys.executable, "env": {"API_KEYS": [OPAQUE, TOKEN]}})
    value = snapshot(collect(home))
    assert len(value["entries"][0]["credentials"]) == 2
    assert OPAQUE not in json.dumps(value) and TOKEN not in json.dumps(value)


@pytest.mark.parametrize("name", ["GOOGLE_APPLICATION_CREDENTIALS", "privateKeyPath", "credentialsPath"])
@pytest.mark.parametrize("placement", ["env", "field", "argument", "dotenv", "auth"])
def test_key_file_references_are_metadata_not_credentials(home, put, monkeypatch, name, placement):
    target = put("private/key.json", TOKEN)
    before = receipt(target)
    server = {"command": sys.executable}
    value = str(home) if name == "credentialsPath" else str(target)
    cfg = {}
    if placement == "env":
        server["env"] = {name: value}
    elif placement == "field":
        server[name] = value
    elif placement == "argument":
        server["args"] = ["--" + name, value]
    elif placement == "dotenv":
        cfg["env_files"] = [str(put(".env", name + "=" + value + "\n"))]
    else:
        put(".codex/auth.json", json.dumps({name: value}))
    source = mcp(put, server, name=str(home))
    opened = []
    original = collectors.bounded_read
    def read(path, *args):
        opened.append(Path(path))
        assert Path(path) != target
        return original(path, *args)
    monkeypatch.setattr(collectors, "bounded_read", read)
    result = snapshot(collect(home, cfg))
    assert not rule(result, "RW-INLINE-SECRET")
    assert all(not e["credentials"] for e in result["entries"])
    refs = [r for e in result["entries"] for r in e.get("key_file_references", [])]
    assert refs == [{"field": ("--" if placement == "argument" else "") + name, "path_hmac": fingerprint(KEY, value)}]
    assert all(f["severity"] == "info" for f in rule(result, "RW-KEY-FILE-REFERENCE"))
    assert rule(result, "RW-KEY-FILE-REFERENCE")
    assert any(e["source"] == str(source) and e["name"] == str(home) for e in result["entries"])
    assert str(target) not in json.dumps(result) and TOKEN not in json.dumps(result)
    assert target not in opened and receipt(target) == before


@pytest.mark.parametrize("name", ["GOOGLE_APPLICATION_CREDENTIALS", "privateKeyPath", "credentialsPath", "MAX_TOKENS", "TOKENIZERS_PARALLELISM"])
def test_provider_token_wins_over_any_reference_or_nonsecret_name(home, put, name):
    mcp(put, {"command": sys.executable, "env": {name: str(home / TOKEN / "key.json")}})
    value = snapshot(collect(home))
    assert rule(value, "RW-INLINE-SECRET")
    assert not rule(value, "RW-KEY-FILE-REFERENCE")
    assert TOKEN not in json.dumps(value)


def test_reference_does_not_hide_other_inline_secret_or_schema(home, put):
    mcp(put, {"command": sys.executable, "credentialsPath": str(home),
              "env": {"API_TOKEN": "partial", "API_KEY": "high"}})
    value = snapshot(collect(home))
    assert value["coverage"] == "complete" and value["baseline_eligible"]
    assert rule(value, "RW-INLINE-SECRET")[0]["severity"] == "high"
    assert value["entries"][0]["source"].startswith(str(home))


def test_reference_change_is_detected_without_retaining_paths(home, put):
    mcp(put, {"command": sys.executable, "credentialsPath": str(home / "first.json")})
    baseline = snapshot(collect(home))
    mcp(put, {"command": sys.executable, "credentialsPath": str(home / "second.json")})
    value = snapshot(collect(home), baseline, True)
    assert value["changes"][0]["fields"] == ["key_file_references"]
    assert "first.json" not in json.dumps(baseline) and "second.json" not in json.dumps(value)


@pytest.mark.parametrize("outside,parent", [(False, False), (True, False), (False, True)])
def test_symlink_coverage_allows_baseline_without_reading_target(home, put, tmp_path, capsys, outside, parent):
    target = (tmp_path if outside else home) / "target.json"
    target.write_text(json.dumps({"mcpServers": {"unread": {"env": {"TOKEN": TOKEN}}}}))
    before = receipt(target)
    if parent:
        (home / ".cursor").symlink_to(target.parent, target_is_directory=True)
    else:
        (home / ".claude.json").symlink_to(target)
    code, value, _ = run(["baseline"], capsys)
    assert code == 1 and value["coverage"] == "partial" and not value["complete"]
    assert value["baseline_eligible"] and value["coverage_warnings"]
    assert TOKEN not in json.dumps(value) and receipt(target) == before
    assert (home / ".local/state/reachward/baseline.json").exists()
    code, value, _ = run(["diff"], capsys)
    assert code == 1 and value["changes"] == []


def test_home_alias_normalized_only_at_root(home, put, tmp_path, monkeypatch, capsys):
    source = mcp(put, {"command": sys.executable})
    before = receipt(source)
    alias = tmp_path / "home-alias"
    alias.symlink_to(home, target_is_directory=True)
    monkeypatch.setenv("HOME", str(alias))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(alias / ".config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(alias / ".local/state"))
    assert locations() == (home, home / ".config", home / ".local/state")
    code, value, _ = run(["baseline"], capsys)
    assert code == 1 and value["baseline_eligible"]
    assert value["coverage"] == "partial" and value["entries"][0]["source"] == str(source)
    assert any("HOME alias resolved" in w["reason"] for w in value["coverage_warnings"])
    assert receipt(source) == before
    for path in (home / ".local/state/reachward").iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    (home / ".claude.json").symlink_to(source)
    code, value, _ = run(["list-sources"], capsys)
    assert code == 1 and len(value["coverage_warnings"]) == 2


def test_missing_reference_warns_explicit_env_file_still_required(home, put, capsys):
    mcp(put, {"command": sys.executable, "envFile": "missing.env"})
    code, value, _ = run(["baseline"], capsys)
    assert code == 1 and value["baseline_eligible"] and value["coverage"] == "partial"
    env = [s for s in value["sources"] if s["collector"] == "env"][0]
    assert not env["required"] and env["coverage"] == "warning"
    assert "missing referenced" in env["status"]
    baseline = home / ".local/state/reachward/baseline.json"
    before = receipt(baseline)
    put(".config/reachward/config.toml", 'env_files=["~/.cursor/missing.env"]\n')
    assert run(["baseline", "--force"], capsys)[0] == 2
    assert receipt(baseline) == before


@pytest.mark.parametrize("skip", ["symlink", "missing_env"])
def test_skipped_source_not_removed_or_added_and_other_changes_survive(home, put, capsys, skip):
    env = put(".cursor/keys.env", "API_KEY=" + OPAQUE + "\n")
    source = mcp(put, {"command": sys.executable, "envFile": "keys.env"})
    other = mcp(put, {"command": sys.executable}, path=".claude.json", name="other")
    assert run(["baseline"], capsys)[0] == 1
    if skip == "symlink":
        source.rename(source.with_suffix(".saved"))
        source.symlink_to(source.with_suffix(".saved"))
    else:
        env.unlink()
    code, value, _ = run(["diff"], capsys)
    assert code == 1 and value["changes"] == [] and value["coverage"] == "partial"
    other.write_text(json.dumps({"mcpServers": {"other": {"command": sys.executable, "args": ["changed"]}}}))
    code, value, _ = run(["diff"], capsys)
    assert code == 1 and len(value["changes"]) == 1 and value["changes"][0]["change"] == "changed"
    assert run(["baseline", "--force"], capsys)[0] == 1
    if skip == "symlink":
        source.unlink()
        source.with_suffix(".saved").rename(source)
    else:
        put(".cursor/keys.env", "API_KEY=" + OPAQUE + "\n")
    code, value, _ = run(["diff"], capsys)
    assert value["changes"] == []  # Coverage recovery alone is not a config addition.
    assert code == 1 and value["comparison_warnings"]
    assert value["coverage"] == "complete"
    run(["baseline", "--force"], capsys)
    code, value, _ = run(["diff"], capsys)
    assert code == 0 and value["comparison_warnings"] == []


def test_ordinary_optional_removal_still_compared(home, put):
    source = mcp(put, {"command": sys.executable})
    baseline = snapshot(collect(home))
    source.unlink()
    value = snapshot(collect(home), baseline, True)
    assert value["coverage"] == "complete" and value["changes"][0]["change"] == "removed"


def test_fixed_command_path_timer_and_derived_diff(home, put, monkeypatch, capsys):
    executable = put("bin/fixture-tool", "#!/bin/sh\nexit 99\n", mode=0o700)
    mcp(put, {"command": "fixture-tool"})
    monkeypatch.setenv("PATH", str(executable.parent))
    before = receipt(executable)
    cfg = {"command_search_path": [str(executable.parent)], "known_servers": ["demo"]}
    baseline = snapshot(collect(home))
    assert baseline["entries"][0]["command_missing"]
    current = snapshot(collect(home, cfg), baseline, True)
    assert not current["entries"][0]["command_missing"] and current["entries"][0]["known"]
    assert current["changes"] == [] and receipt(executable) == before
    put(".config/reachward/config.toml", 'command_search_path=["~/bin", "/usr/bin"]\n')
    code, units, _ = run(["print-timer"], capsys)
    assert code == 0 and 'Environment="PATH=' + str(home / "bin") + ':/usr/bin"' in units["reachward.service"]
    assert not (home / ".local/state/reachward").exists()


@pytest.mark.parametrize("value", [[], "PATH", ["relative"], [""], ["/bin:/other"], ["/bin\nExecStart=bad"]])
def test_command_path_rejects_ambient_or_unsafe_values(home, value):
    with pytest.raises(SafeError):
        command_search_path({"command_search_path": value}, home)


def test_timer_custom_config_and_unit_escaping(home, put, capsys):
    path = put('config "$rate%".toml', 'command_search_path=["~/bin%tools"]\n')
    code, units, _ = run(["--config", str(path), "print-timer"], capsys)
    assert code == 0
    assert 'Environment="PATH=' + str(home / "bin%%tools") + '"' in units["reachward.service"]
    assert '--config "' in units["reachward.service"] and '$$rate%%' in units["reachward.service"]
    assert '\\"' in units["reachward.service"]


def test_timer_rejects_secret_shaped_path_without_echoing(home, put, capsys):
    put(".config/reachward/config.toml", 'command_search_path=["~/' + TOKEN + '"]\n')
    code, value, error = run(["print-timer"], capsys)
    assert code == 2 and value is None and TOKEN not in error


def test_online_scope_metadata_excluded_but_declared_scope_changes_retained(home, put, monkeypatch):
    put(".config/gh/hosts.yml", "github.com:\n    user: fixture\n")
    mcp(put, {"command": sys.executable, "scopes": ["read:user"]})
    baseline = snapshot(collect(home))
    observed = []
    def run(argv, **kwargs):
        observed.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"HTTP/2 200 OK\r\nX-OAuth-Scopes: repo\r\n\r\n")
    monkeypatch.setattr(subprocess, "run", run)
    inventory = collect(home)
    online_scopes(inventory)
    value = snapshot(inventory, baseline, True)
    assert value["changes"] == [] and rule(value, "RW-BROAD-SCOPE")
    assert observed[0][0] == ["gh", "api", "-i", "/user"]
    assert observed[0][1]["env"]["PATH"] == inventory.command_path
    assert snapshot(collect(home), value, True)["changes"] == []
    mcp(put, {"command": sys.executable, "scopes": ["repo"]})
    changed = snapshot(collect(home), baseline, True)
    assert changed["changes"][0]["fields"] == ["scopes"]
