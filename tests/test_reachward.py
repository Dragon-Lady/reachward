from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from reachward import alerts
from reachward.audit import changes, snapshot, online_scopes
from reachward.cli import main
from reachward.collectors import Inventory, unpinned
from reachward.safety import Store, SafeError, bounded_read, fingerprint, write_private, MAX_BYTES

KEY = bytes(range(32))
CANARY = "gh" + "p_" + hashlib.sha256(b"synthetic fixture only").hexdigest()[:36]
OPAQUE = "synthetic-" + hashlib.sha256(b"arbitrary credential").hexdigest()


def inv(home, cfg=None, now=None):
    return Inventory(home, home / ".config", cfg or {}, KEY, now=now).collect()


def mcp(put, server=None, name="demo", path=".cursor/mcp.json"):
    server = server if server is not None else {"command": sys.executable, "args": ["-m", "example"]}
    return put(path, json.dumps({"mcpServers": {name: server}}))


def rules(value):
    return {f["rule"] for f in value["findings"]}


def state(home):
    return home / ".local/state/reachward"


def run(args, capsys):
    code = main(args + ["--format", "json"])
    output = capsys.readouterr()
    return code, json.loads(output.out) if output.out else None, output.err


@pytest.fixture
def all_sources(put, home):
    server = {"command": sys.executable, "args": ["--token", OPAQUE], "env": {"API_TOKEN": CANARY}, "envFile": str(home / ".env")}
    mcp(put, server)
    put(".codex/config.toml", '[mcp_servers.demo]\ncommand = "python3"\nargs = ["--token", "' + OPAQUE + '"]\n[mcp_servers.demo.env]\nAPI_TOKEN = "' + CANARY + '"\n')
    put(".codex/auth.json", json.dumps({"auth_mode": "chatgpt", "tokens": {"access_token": CANARY, "refresh_token": OPAQUE}}))
    mcp(put, server, path=".claude.json")
    mcp(put, server, path=".config/Claude/claude_desktop_config.json")
    put(".config/Code/User/mcp.json", json.dumps({"servers": {"demo": server}}))
    mcp(put, server, path=".codeium/windsurf/mcp_config.json")
    mcp(put, server, path=".gemini/settings.json")
    put(".config/gh/hosts.yml", "github.com:\n    user: example-user\n    oauth_token: " + CANARY + "\n    users:\n        example-user:\n            oauth_token: " + CANARY + "\n")
    put(".config/rclone/rclone.conf", '[cloud]\ntype = drive\nscope = drive\ntoken = ' + json.dumps({"refresh_token": OPAQUE, "access_token": CANARY, "expiry": "2020-01-01T00:00:00Z"}) + "\n")
    put(".env", "API_TOKEN=" + CANARY + "\nPRIVATE_PASSWORD='" + OPAQUE + "'\n")
    put(".config/reachward/cloud_connectors.toml", '[[connectors]]\nname = "Cloud mail"\nscopes = ["https://mail.google.com/"]\nreview_by = "2020-01-01"\n')
    # Referenced relative env paths must really exist for every sample collector.
    for relative in (".config/.env", ".config/Code/.env", ".codeium/.env"):
        put(relative, "API_TOKEN=" + CANARY + "\n")
    return home


def test_collectors(all_sources):
    value = snapshot(inv(all_sources))
    assert value["complete"], value["sources"]
    assert {e["collector"] for e in value["entries"]} == {"cursor", "codex", "codex-auth", "claude", "vscode", "other", "gh", "rclone", "env", "manual"}
    assert {"RW-INLINE-SECRET", "RW-DUP-CREDENTIAL", "RW-BROAD-SCOPE", "RW-STALE", "RW-UNKNOWN-SERVER"} <= rules(value)


@pytest.mark.parametrize("format", ["text", "json", "md", "html"])
def test_canaries_every_command_format(all_sources, capsys, format, monkeypatch):
    home = all_sources
    def blocked(*a, **k):
        raise AssertionError("network/subprocess attempted offline")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    calls = [["scan"], ["baseline"], ["diff"], ["scan", "--diff"], ["list-sources"],
             ["known", "add", "demo"], ["known", "list"], ["known", "remove", "demo"],
             ["report"], ["report", "--send"], ["print-timer"]]
    for number, args in enumerate(calls):
        output = home / f"report-{number}.{format}"
        code = main(args + ["--format", format, "--output", str(output)])
        assert code in (0, 1), (args, capsys.readouterr())
        text = output.read_text()
        observed = capsys.readouterr()
        for secret in (CANARY, OPAQUE):
            assert secret not in text + observed.out + observed.err
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
    for path in state(home).iterdir():
        if path.name != "fp.key":
            for secret in (CANARY.encode(), OPAQUE.encode()):
                assert secret not in path.read_bytes()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(state(home).stat().st_mode) == 0o700


def test_target_bytes_metadata_unchanged(all_sources, capsys):
    paths = [p for p in all_sources.rglob("*") if p.is_file()]
    def receipt(p):
        s = p.stat()
        return hashlib.sha256(p.read_bytes()).hexdigest(), s.st_size, s.st_mtime_ns, s.st_mode, s.st_ino
    before = {p: receipt(p) for p in paths}
    assert main(["scan"]) == 1
    assert {p: receipt(p) for p in paths} == before


@pytest.mark.parametrize("rule,positive", [(rule, positive) for rule in
    ["RW-INLINE-SECRET", "RW-FILE-MODE", "RW-BROAD-SCOPE", "RW-STALE", "RW-UNKNOWN-SERVER", "RW-UNPINNED-LAUNCH", "RW-DUP-CREDENTIAL"] for positive in (False, True)])
def test_rules_positive_negative(home, put, rule, positive):
    cfg = {"known_servers": ["demo"]}
    server = {"command": sys.executable, "args": [], "env": {"API_TOKEN": "${API_TOKEN}"}}
    if rule == "RW-INLINE-SECRET" and positive:
        server["env"]["API_TOKEN"] = OPAQUE
    if rule == "RW-FILE-MODE":
        server["env"]["API_TOKEN"] = OPAQUE
    if rule == "RW-BROAD-SCOPE":
        server["scopes"] = ["repo" if positive else "read:user"]
    if rule == "RW-STALE" and positive:
        server["command"] = "a-command-that-does-not-exist-in-this-fixture"
    if rule == "RW-UNKNOWN-SERVER" and positive:
        cfg["known_servers"] = []
    if rule == "RW-UNPINNED-LAUNCH":
        server.update(command="npx", args=["-y", "example-package" if positive else "example-package@1.2.3"])
    if rule == "RW-DUP-CREDENTIAL":
        server["env"]["API_TOKEN"] = OPAQUE
        mcp(put, {"command": sys.executable, "env": {"API_TOKEN": OPAQUE if positive else "different-fake-credential"}}, "second", ".claude.json")
    path = mcp(put, server)
    if rule == "RW-FILE-MODE" and positive:
        path.chmod(0o644)
    assert (rule in rules(snapshot(inv(home, cfg)))) is positive


@pytest.mark.parametrize("positive", [False, True])
def test_server_changed_rule(home, put, positive):
    mcp(put)
    baseline = snapshot(inv(home, {"known_servers": ["demo"]}))
    mcp(put, {"command": sys.executable, "args": ["-m", "changed" if positive else "example"]})
    value = snapshot(inv(home, {"known_servers": ["demo"]}), baseline, True)
    assert ("RW-SERVER-CHANGED" in rules(value)) is positive


def test_baseline_mutations_exact(home, put, capsys):
    path = mcp(put)
    assert run(["baseline"], capsys)[0] == 1
    assert run(["diff"], capsys)[0] == 0
    doc = json.loads(path.read_text())
    doc["mcpServers"]["added"] = {"command": sys.executable}
    path.write_text(json.dumps(doc))
    code, value, _ = run(["diff"], capsys)
    assert code == 1
    assert [c["change"] for c in value["changes"]] == ["added"]
    run(["baseline", "--force"], capsys)
    doc["mcpServers"]["demo"]["args"] = ["new-argument"]
    path.write_text(json.dumps(doc))
    code, value, _ = run(["diff"], capsys)
    assert code == 1 and len(value["changes"]) == 1
    assert "args_hmac" in value["changes"][0]["fields"]
    run(["baseline", "--force"], capsys)
    path.chmod(0o644)
    code, value, _ = run(["diff"], capsys)
    assert code == 1 and len(value["changes"]) == 2
    assert all(c["fields"] == ["mode"] for c in value["changes"])


def test_invalid_source_cannot_replace_baseline(home, put, capsys):
    path = mcp(put)
    run(["baseline"], capsys)
    before = (state(home) / "baseline.json").read_bytes()
    path.write_text('{"bad": ' + OPAQUE)
    assert run(["diff"], capsys)[0] == 2
    assert run(["baseline", "--force"], capsys)[0] == 2
    assert (state(home) / "baseline.json").read_bytes() == before
    code, value, error = run(["list-sources"], capsys)
    assert code == 2 and not value["complete"]
    assert OPAQUE not in json.dumps(value) + error


@pytest.mark.parametrize("prefix", ["", "# Encrypted rclone configuration File\n\n", "\n  # comment\n ; comment\n\n"])
def test_encrypted_rclone(home, put, prefix):
    put(".config/rclone/rclone.conf", prefix + "RCLONE_ENCRYPT_V0:\nnot-a-real-encrypted-payload\n")
    value = snapshot(inv(home))
    assert value["complete"] and value["entries"][0]["token_storage"] == "encrypted: not inspected"
    assert any(s["status"] == "encrypted: not inspected" for s in value["sources"])


def test_manual_review_and_rclone_expiry(home, put):
    now = datetime.now(timezone.utc)
    for old in (False, True):
        date = (now + timedelta(days=-100 if old else 100)).date()
        put(".config/reachward/cloud_connectors.toml", f'[[connectors]]\nname="connector"\nreview_by={date.isoformat()}\n')
        put(".config/rclone/rclone.conf", '[drive]\ntype = drive\nscope = drive.readonly\ntoken = ' + json.dumps({"expiry": date.isoformat() + "T00:00:00Z"}) + "\n")
        assert ("RW-STALE" in rules(snapshot(inv(home, now=now)))) is old


def test_age_is_metadata_not_token_validity(home, put):
    path = put(".codex/auth.json", json.dumps({"OPENAI_API_KEY": CANARY}))
    now = datetime.now(timezone.utc)
    for days in (1, 100):
        age = now.timestamp() - days * 86400
        os.utime(path, (age, age))
        assert ("RW-STALE" in rules(snapshot(inv(home, now=now)))) is (days > 90)


def test_gh_online_exact_command_headers_only(home, put, monkeypatch):
    put(".config/gh/hosts.yml", "github.com:\n    user: example\n")
    observed = []
    def execute(argv, **kwargs):
        observed.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=b'HTTP/2.0 200 OK\r\nX-OAuth-Scopes: repo, read:org\r\n\r\n' + OPAQUE.encode())
    monkeypatch.setattr(subprocess, "run", execute)
    inventory = inv(home)
    assert observed == []
    online_scopes(inventory)
    value = snapshot(inventory)
    assert observed[0][0] == ["gh", "api", "-i", "/user"] and len(observed) == 1
    assert observed[0][1]["timeout"] == 5
    assert value["entries"][0]["scopes"] == ["read:org", "repo"]
    assert OPAQUE not in json.dumps(value)
    assert "RW-BROAD-SCOPE" in rules(value)


def test_online_failure_never_echoes_error(home, put, monkeypatch, capsys):
    def fail(*a, **k):
        raise subprocess.TimeoutExpired(OPAQUE, 5, output=CANARY)
    monkeypatch.setattr(subprocess, "run", fail)
    assert main(["scan", "--online"]) == 2
    text = capsys.readouterr()
    assert CANARY not in text.err and OPAQUE not in text.err


def test_html_escapes_labels(home, put, capsys):
    label = "<script>alert(1)</script>"
    mcp(put, name=label)
    assert main(["scan", "--format", "html"]) == 1
    output = capsys.readouterr().out
    assert label not in output and "&lt;script&gt;alert(1)&lt;/script&gt;" in output


def test_jsonc_claude_projects_roots_extras(home, put):
    put(".config/Code/User/mcp.json", '{// comment\n"servers":{"demo":{"url":"https://example.test/mcp",},},}')
    put(".claude.json", json.dumps({"projects": {"project": {"mcpServers": {"demo": {"command": sys.executable}}}}}))
    mcp(put, path="project/.mcp.json")
    mcp(put, path="extra.json")
    inventory = Inventory(home, home / ".config", {"extra_sources": [{"path": str(home / "extra.json")}]}, KEY).collect([home / "project"])
    value = snapshot(inventory)
    assert value["complete"] and len(value["entries"]) == 4


@pytest.mark.parametrize("cmd,args,expected", [("npx", ["-y", "example@latest"], True), ("npx", ["-y", "@scope/example@1.2.3"], False), ("uvx", ["example"], True), ("uvx", ["example==1.2.3"], False), ("pipx", ["run", "example"], True), ("pipx", ["run", "example==1.2.3"], False), ("python", [], False)])
def test_launch_pin(cmd, args, expected):
    assert unpinned(cmd, args) is expected


def test_url_args_headers_never_retained(home, put):
    mcp(put, {"url": "https://user:" + OPAQUE + "@example.test/path?token=" + CANARY,
              "headers": {"Authorization": "Bearer " + OPAQUE}, "args": ["--password=" + CANARY]})
    value = snapshot(inv(home))
    text = json.dumps(value)
    assert CANARY not in text and OPAQUE not in text
    assert value["entries"][0]["url_host"] == "example.test"
    assert "RW-INLINE-SECRET" in rules(value)


def test_symlinks_fifo_oversize_refused(home, put, tmp_path):
    outside = tmp_path / "outside"
    outside.write_text(OPAQUE)
    path = home / "link"
    path.symlink_to(outside)
    with pytest.raises(OSError):
        bounded_read(path, home)
    path.unlink()
    os.mkfifo(path)
    with pytest.raises(SafeError):
        bounded_read(path, home)
    large = put("large", "")
    with large.open("wb") as stream:
        stream.truncate(MAX_BYTES + 1)
    with pytest.raises(SafeError):
        bounded_read(large, home)
    with pytest.raises(SafeError):
        bounded_read(outside, home)


def test_parent_symlink_rejected(home, tmp_path):
    target = tmp_path / "other"
    target.mkdir()
    (target / "config.json").write_text("{}")
    (home / "linked").symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError):
        bounded_read(home / "linked/config.json", home)


def test_private_write_no_overwrite_or_hardlink_damage(home, put):
    path = put("source", OPAQUE)
    with pytest.raises(FileExistsError):
        write_private(path, "replacement")
    hard = home / "hardlink"
    os.link(path, hard)
    with pytest.raises(SafeError):
        write_private(hard, "replacement", replace=True)
    assert path.read_text() == OPAQUE


def test_created_files_private_from_first_open(home, monkeypatch):
    calls = []
    original = os.open
    def record(path, flags, mode=0o777, **kwargs):
        if flags & os.O_CREAT:
            calls.append(mode)
        return original(path, flags, mode, **kwargs)
    monkeypatch.setattr(os, "open", record)
    store = Store(state(home))
    store.save("last.json", {})
    assert calls and all(mode == 0o600 for mode in calls)


def test_missing_key_does_not_silently_rekey(home):
    store = Store(state(home))
    store.save("baseline.json", {})
    (state(home) / "fp.key").unlink()
    with pytest.raises(SafeError):
        Store(state(home))


def test_fp_key_is_machine_specific(home):
    first = Store(state(home))
    second = Store(home / "other-state")
    assert first.key != second.key
    assert fingerprint(first.key, CANARY) != fingerprint(second.key, CANARY)
    assert len(fingerprint(first.key, CANARY)) == 19


def test_modes_fail_closed(home, put, capsys):
    put(".config/reachward/config.toml", "known_servers=[]\n", mode=0o644)
    assert main(["scan"]) == 2
    assert not state(home).exists()


def test_aggregate_alerts_dedupe_fail_retry(home, monkeypatch):
    store = Store(state(home))
    sent = []
    def capture(channel, cfg, message):
        sent.append((channel, message))
        if channel == "email":
            raise ValueError(OPAQUE)
    monkeypatch.setattr(alerts, "send_one", capture)
    finding = {"rule": "RW-INLINE-SECRET", "severity": "high", "entry": "entry", "reason": str(home) + OPAQUE}
    cfg = {"alert_channels": ["slack", "email"]}
    first = alerts.deliver(cfg, store, [finding], [], now=100000)
    second = alerts.deliver(cfg, store, [finding], [], now=100001)
    assert first["delivered"] == ["slack"] and first["failed"] == ["email"]
    assert second["deduped"] == ["slack"] and second["failed"] == ["email"]
    assert all(OPAQUE not in msg and str(home) not in msg for _, msg in sent)
    assert all(msg.endswith("run `reachward report` locally for details") for _, msg in sent)
    assert alerts.deliver(cfg, store, [finding], [], now=200000)["delivered"] == ["slack"]


@pytest.mark.parametrize("url", ["http://example.test/x", "https://user:pass@example.test/x", "file:///etc/passwd", "https://example.test/#frag"])
def test_alert_destinations_reject_unsafe(url):
    with pytest.raises(SafeError):
        alerts.endpoint(url)


def test_alert_transports_do_not_leak(home, monkeypatch):
    captured = []
    monkeypatch.setenv("TEST_WEBHOOK", "https://example.test/" + OPAQUE)
    monkeypatch.setenv("TEST_TOKEN", CANARY)
    def post(url, body, headers):
        captured.append((body, headers))
    monkeypatch.setattr(alerts, "post", post)
    alerts.send_one("slack", {"alert_slack_webhook_env": "TEST_WEBHOOK"}, "safe aggregate")
    alerts.send_one("ntfy", {"alert_ntfy_topic": "fixture", "alert_ntfy_token_env": "TEST_TOKEN"}, "safe aggregate")
    assert all(CANARY.encode() not in body and OPAQUE.encode() not in body for body, _ in captured)
    assert captured[1][1]["Authorization"] == "Bearer " + CANARY


def test_no_redirect():
    assert alerts.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.test") is None


def test_timer_prints_only(home, capsys):
    assert main(["print-timer"]) == 0
    assert "OnUnitActiveSec=1h" in capsys.readouterr().out
    assert not state(home).exists()


def test_usage_errors_redacted(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--" + CANARY])
    assert exc.value.code == 2
    assert CANARY not in capsys.readouterr().err


def test_reference_headers_not_inline(home, put):
    mcp(put, {"url": "https://example.test", "headers": {"Authorization": "Bearer ${ENV_TOKEN}"}})
    assert "RW-INLINE-SECRET" not in rules(snapshot(inv(home)))


def test_opaque_header_argument(home, put):
    mcp(put, {"command": sys.executable, "args": ["-H", "Authorization: Bearer " + OPAQUE]})
    value = snapshot(inv(home))
    assert "RW-INLINE-SECRET" in rules(value)
    assert fingerprint(KEY, OPAQUE) in value["entries"][0]["credentials"]


def test_redacted_labels_do_not_cause_permanent_diff(home, put):
    mcp(put, {"command": sys.executable, "env": {"API_TOKEN": OPAQUE}}, name=OPAQUE)
    baseline = snapshot(inv(home))
    value = snapshot(inv(home), baseline, True)
    assert value["changes"] == []


def test_encrypted_file_mode_still_checked(home, put):
    put(".config/rclone/rclone.conf", "# Encrypted rclone configuration File\n\nRCLONE_ENCRYPT_V0:\nopaque\n", mode=0o644)
    assert "RW-FILE-MODE" in rules(snapshot(inv(home)))


def test_uvx_at_pin():
    assert not unpinned("uvx", ["example@1.2.3"])


def test_corrupt_gh_yaml_incomplete(home, put):
    put(".config/gh/hosts.yml", "github.com:\n    oauth_token: |\n       " + OPAQUE)
    value = snapshot(inv(home))
    assert not value["complete"] and OPAQUE not in json.dumps(value)


def test_secret_cannot_rewrite_severity_or_schema(home, put):
    mcp(put, {"command": sys.executable, "env": {"API_TOKEN": "high", "API_KEY": "source"}})
    value = snapshot(inv(home))
    assert value["entries"][0]["source"]
    assert any(f["rule"] == "RW-INLINE-SECRET" and f["severity"] == "high" for f in value["findings"])


@pytest.mark.parametrize("name", ["PATH", "NODE_PATH", "PYTHONPATH", "CODEX_CLI_PATH",
                                 "NODE_REPL_NODE_PATH", "NODE_REPL_TRUSTED_CODE_PATHS",
                                 "OTHER_PATHS", "projectPath", "KEYBOARD"])
def test_nonsecret_names_do_not_hide_paths_or_raise_inline(home, put, name):
    path_value = str(home / "tools")
    source = mcp(put, {"command": sys.executable, "env": {name: path_value},
                       name: path_value, "args": ["--" + name, path_value]}, name=path_value)
    value = snapshot(inv(home))
    entry = value["entries"][0]
    assert "RW-INLINE-SECRET" not in rules(value)
    assert entry["credentials"] == []
    assert entry["name"] == path_value and entry["source"] == str(source)


@pytest.mark.parametrize("name", ["PAT", "GH_PAT", "GITHUB_PAT", "pat-value", "KEY",
                                 "API_KEY", "apiKey", "apikey", "clientSecret"])
def test_secret_names_still_detect_and_redact(home, put, name):
    mcp(put, {"command": sys.executable, "env": {name: OPAQUE}}, name=OPAQUE)
    value = snapshot(inv(home))
    assert "RW-INLINE-SECRET" in rules(value)
    assert value["entries"][0]["credentials"] == [fingerprint(KEY, OPAQUE)]
    assert OPAQUE not in json.dumps(value)


def test_path_name_with_recognized_token_still_detected(home, put):
    mcp(put, {"command": sys.executable, "env": {"PATH": CANARY}})
    value = snapshot(inv(home))
    assert "RW-INLINE-SECRET" in rules(value)
    assert CANARY not in json.dumps(value)


def test_env_path_names_ignored_but_pat_kept(home, put):
    path = put(".env", "PATH=/usr/bin\nNODE_PATH=/opt/example\nPYTHONPATH=/opt/python\nGH_PAT=" + OPAQUE + "\n")
    value = snapshot(inv(home, {"env_files": [str(path)]}))
    assert [e["env_names"] for e in value["entries"]] == [["GH_PAT"]]
    assert OPAQUE not in json.dumps(value)


def test_rclone_marker_in_plaintext_section_is_not_encrypted(home, put):
    put(".config/rclone/rclone.conf", "# ordinary config\n[cloud]\ntype = local\nRCLONE_ENCRYPT_V0: ordinary-value\n")
    value = snapshot(inv(home))
    assert value["complete"]
    assert value["entries"][0]["name"] == "cloud"
    assert not any(s["status"] == "encrypted: not inspected" for s in value["sources"])
