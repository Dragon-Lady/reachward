#!/usr/bin/env python3
"""Reproduce a directory-permission finding using an installed Reach Ward."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


class CheckFailed(Exception):
    pass


def check(condition, message):
    if not condition:
        raise CheckFailed(message)


def write_private(path, content):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)


def receipt(path):
    info = path.stat()
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": info.st_size, "mtime_ns": info.st_mtime_ns,
            "inode": info.st_ino, "mode": format(stat.S_IMODE(info.st_mode), "04o")}


def run_cli(home, env, *arguments):
    # Isolated import mode selects this interpreter's installed package, never
    # a package from the current directory or inherited PYTHONPATH.
    return subprocess.run([sys.executable, "-I", "-B", "-m", "reachward", *arguments],
                          cwd=home, env=env, capture_output=True, text=True,
                          timeout=30, check=False)


def demonstrate(base):
    home = base / "home"
    home.mkdir(mode=0o700)
    config_home = home / ".config"
    config_home.mkdir(mode=0o700)
    config_dir = config_home / "reachward"
    config_dir.mkdir(mode=0o700)
    settings = home / ".codex"
    settings.mkdir(mode=0o700)
    reports = base / "reports"
    reports.mkdir(mode=0o700)
    config = config_dir / "config.toml"
    write_private(config, "alert_channels = []\n")

    # This is a generated, fake fixture value, never an account credential.
    canary = "sk" + "-" + "POC_ONLY_NOT_A_REAL_CREDENTIAL_00000000"
    auth = settings / "auth.json"
    write_private(auth, json.dumps({"auth_mode": "api_key", "OPENAI_API_KEY": canary}))
    settings.chmod(0o775)  # Only a new fixture under the private 0700 root.

    # Explicit source overrides also keep an inherited gh/rclone configuration
    # outside this experiment. No real account environment is passed through.
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(config_home),
           "XDG_STATE_HOME": str(home / ".local/state"),
           "XDG_DATA_HOME": str(home / ".local/share"),
           "XDG_CACHE_HOME": str(home / ".cache"),
           "GH_CONFIG_DIR": str(config_home / "gh"),
           "RCLONE_CONFIG": str(config_home / "rclone/rclone.conf"),
           "PATH": os.defpath, "LC_ALL": "C.UTF-8"}
    version = run_cli(home, env, "--version")
    check(version.returncode == 0, "Install Reach Ward in the interpreter used to run this script.")
    results = {}
    original = {"auth.json": receipt(auth), "config.toml": receipt(config)}
    for phase, mode, expected_exit in [("before", 0o775, 1), ("after", 0o700, 0)]:
        if phase == "after":
            settings.chmod(mode)  # The operator correction, outside the scan.
        before = {"auth.json": receipt(auth), "config.toml": receipt(config)}
        result = run_cli(home, env, "--config", str(config), "scan", "--format", "json",
                         "--output", str(reports / (phase + ".json")))
        check(canary not in result.stdout + result.stderr, "Canary appeared in command output.")
        check(result.returncode == expected_exit, "Unexpected scanner exit status.")
        check(before == {"auth.json": receipt(auth), "config.toml": receipt(config)},
              "A scan changed a fixture file.")
        check(stat.S_IMODE(settings.stat().st_mode) == mode, "A scan changed the fixture directory mode.")
        report_path = reports / (phase + ".json")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        check(report["complete"], "Fixture inventory was incomplete.")
        check(len(report["entries"]) == 1 and report["entries"][0]["collector"] == "codex-auth",
              "Unexpected inventory; expected only the synthetic authentication source.")
        check(len(report["entries"][0]["credentials"]) == 1, "Fixture credential was not fingerprinted.")
        findings = [(item["rule"], item["severity"]) for item in report["findings"]]
        check(findings == ([("RW-FILE-MODE", "high")] if phase == "before" else []),
              "Unexpected permission findings.")
        results[phase] = {"directory_mode": format(mode, "04o"), "scan_exit": result.returncode,
                          "findings": findings, "fixture_files_unchanged": True}

    check(original == {"auth.json": receipt(auth), "config.toml": receipt(config)},
          "Fixture files changed between phases.")
    state = home / ".local/state/reachward"
    check(stat.S_IMODE(state.stat().st_mode) == 0o700, "State directory is not private.")
    for folder in (reports, state):
        for path in folder.iterdir():
            check(path.is_file() and not path.is_symlink(), "Unexpected output type.")
            check(stat.S_IMODE(path.stat().st_mode) == 0o600, "Output file is not private.")
            check(canary.encode() not in path.read_bytes(), "Canary appeared in a report or state file.")
    write_private(reports / "verification.json", json.dumps({"package_version": version.stdout.strip(),
        "results": results, "fixture_receipts": original, "canary_absent_from_outputs": True,
        "private_output_modes": True}, indent=2) + "\n")
    print("PASS: before: directory 0775, RW-FILE-MODE high, scan exit 1")
    print("PASS: after:  directory 0700, no findings, scan exit 0")
    print("PASS: fixture file bytes, size, mtime, inode and modes preserved")
    print("PASS: fake credential absent from command output, reports and state")
    print("PASS: state directory 0700; report and state files 0600")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="retain the private temporary fixture and reports")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        print("This permission demonstration requires Linux.", file=sys.stderr)
        return 2
    os.umask(0o077)
    base = Path(tempfile.mkdtemp(prefix="reachward-permission-poc-")).resolve()
    try:
        demonstrate(base)
        return 0
    except CheckFailed as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        print("FAIL: fixture setup, scan or verification did not complete.", file=sys.stderr)
        return 1
    finally:
        if args.keep:
            print("Private fixture retained at: " + str(base))
        else:
            shutil.rmtree(base)


if __name__ == "__main__":
    raise SystemExit(main())
