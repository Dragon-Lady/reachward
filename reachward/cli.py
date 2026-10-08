import argparse
from datetime import datetime, timedelta, timezone
import html
import json
import re
import sys

from . import __version__
from .alerts import deliver
from .audit import online_scopes, snapshot
from .collectors import Inventory
from .config import load_config, locations
from .safety import absolute, Redactor, SafeError, Store, write_private


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally repeats user arguments, which can contain a secret.
        self.exit(2, "reachward: invalid arguments; use --help\n")


def parser():
    p = Parser(prog="reachward", description="Local agent permission inventory; offline and read-only toward targets.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--config", help="private TOML config (default: XDG config directory)")
    commands = p.add_subparsers(dest="command", required=True)
    for name in ("scan", "baseline", "diff", "list-sources", "known", "report", "print-timer"):
        sub = commands.add_parser(name)
        sub.add_argument("--format", choices=("text", "json", "md", "html"), default="text")
        sub.add_argument("--output", help="create a new 0600 report file; never overwrites")
        if name in {"scan", "baseline", "diff", "list-sources"}:
            sub.add_argument("--roots", nargs="*", default=[])
        if name in {"scan", "baseline", "diff"}:
            sub.add_argument("--online", action="store_true", help="opt in to the single gh api -i /user scope check")
        if name == "scan":
            sub.add_argument("--diff", action="store_true")
        if name == "baseline":
            sub.add_argument("--force", action="store_true")
        if name == "known":
            sub.add_argument("action", choices=("add", "remove", "list"))
            sub.add_argument("name", nargs="?")
        if name == "report":
            sub.add_argument("--since", default="7d")
            sub.add_argument("--send", action="store_true")
        if name == "print-timer":
            sub.add_argument("--interval", default="1h")
    return p


def render(value, format):
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)
    if format == "html":
        return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Reach Ward</title><body><h1>Reach Ward</h1><pre>' + html.escape(text) + "</pre></body></html>\n"
    if format == "md":
        return "# Reach Ward\n\n```json\n" + text.replace("`", "\\u0060") + "\n```\n"
    if format == "text":
        return "Reach Ward\n" + text + "\n"
    return text + "\n"


def timer(interval):
    if not re.fullmatch(r"[1-9]\d{0,5}[smhd]", interval):
        raise SafeError("interval must be a positive number followed by s, m, h or d")
    return {"reachward.service": "[Unit]\nDescription=Reach Ward offline inventory\n\n[Service]\nType=oneshot\nExecStart=%h/.local/bin/reachward scan --diff\nSuccessExitStatus=1\nUMask=0077\nNoNewPrivileges=true\n",
            "reachward.timer": "[Unit]\nDescription=Reach Ward inventory timer\n\n[Timer]\nOnBootSec=5m\nOnUnitActiveSec=" + interval + "\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"}


def history(store, value):
    entries = store.read("history.json", [])
    cutoff = (datetime.fromisoformat(value["time"]) - timedelta(days=30)).isoformat()
    entries = [v for v in entries if v["time"] >= cutoff][-999:]
    counts = {}
    for f in value["findings"]:
        counts[f["rule"]] = counts.get(f["rule"], 0) + 1
    entries.append({"time": value["time"], "complete": value["complete"], "entries": len(value["entries"]), "findings": counts, "changes": len(value["changes"])})
    store.save("history.json", entries)


def execute(args):
    if args.command == "print-timer":
        return timer(args.interval), 0
    home, config_home, state_home = locations()
    cfg = load_config(absolute(args.config) if args.config else config_home / "reachward/config.toml")
    store = Store(state_home / "reachward")
    known = store.read("known.json", [])
    if args.command == "known":
        if args.action != "list" and not args.name:
            raise SafeError("known add/remove needs a server name")
        if args.action == "list" and args.name:
            raise SafeError("known list takes no name")
        if args.action == "add":
            known = sorted(set(known) | {args.name})
        if args.action == "remove":
            if args.name in cfg.get("known_servers", []):
                raise SafeError("server is configured in known_servers; edit that config explicitly")
            known = [name for name in known if name != args.name]
        redactor = Redactor(store.key)
        redactor.discover(known)
        if args.action != "list":
            store.save("known.json", redactor.clean(known))
        return {"known_servers": redactor.clean(sorted(set(known) | set(cfg.get("known_servers", []))))}, 0
    if args.command == "report":
        match = re.fullmatch(r"([1-9]\d{0,4})([hd])", args.since)
        if not match:
            raise SafeError("since must be a positive number of hours or days")
        value = store.read("last.json")
        if value is None:
            raise SafeError("no saved scan; run scan first")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=int(match[1]) * (24 if match[2] == "d" else 1))
        value["history"] = [v for v in store.read("history.json", []) if datetime.fromisoformat(v["time"]) >= cutoff]
        if args.send:
            value["alerts"] = deliver(cfg, store, value["findings"], value["changes"])
        return value, status(value)
    inv = Inventory(home, config_home, cfg, store.key, known).collect(args.roots)
    if args.command == "list-sources":
        value = snapshot(inv)
        return {"sources": value["sources"], "complete": value["complete"]}, 0 if value["complete"] else 2
    if args.online:
        online_scopes(inv)
    baseline = store.read("baseline.json")
    value = snapshot(inv, baseline, args.command == "diff" or getattr(args, "diff", False))
    if args.command == "baseline":
        if not value["complete"]:
            raise SafeError("incomplete inventory; baseline refused (run list-sources)")
        if baseline is not None and not args.force:
            raise SafeError("baseline exists; use --force after review")
        # A baseline records the inventory, not an approval of any findings.
        store.save("baseline.json", {"schema": 1, "time": value["time"], "entries": value["entries"]})
    elif args.command in {"scan", "diff"}:
        alert_findings = [f for f in value["findings"] if f["severity"] == "high"]
        if alert_findings or value["changes"]:
            value["alerts"] = deliver(cfg, store, alert_findings, value["changes"])
    store.save("last.json", value)
    history(store, value)
    if args.command == "diff":
        # Exit status reflects changes only; current advisories remain visible.
        return value, 2 if not value["complete"] or value.get("alerts", {}).get("failed") else int(bool(value["changes"]))
    return value, status(value)


def status(value):
    if not value.get("complete", True) or value.get("alerts", {}).get("failed"):
        return 2
    return int(bool(value.get("findings") or value.get("changes")))


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        value, code = execute(args)
        result = render(value, args.format)
        if args.command == "print-timer" and args.format == "text":
            result = "\n".join("# " + name + "\n" + unit for name, unit in value.items())
        if args.output:
            write_private(absolute(args.output), result)
        else:
            sys.stdout.write(result)
        return code
    except SafeError as exc:
        sys.stderr.write("reachward: " + str(exc) + "\n")
        return 2
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        # Do not print parser context, URLs, file contents or exception arguments.
        sys.stderr.write("reachward: operation failed; check configuration, source status and private file modes\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
