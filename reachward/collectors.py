"""Collectors parse data only. No server startup, shell, eval, or keyring reads."""
import configparser
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import stat
from urllib.parse import urlsplit, parse_qsl, unquote

from .config import tomllib
from .safety import (absolute, bounded_read, fingerprint, is_value, read_error,
                     Redactor, SafeError, SECRET_NAME, TOKEN)


def scopes(value):
    if isinstance(value, str):
        return sorted(set(value.replace(",", " ").split()))
    if isinstance(value, list):
        return sorted(set(x for x in value if isinstance(x, str)))
    return []


def unpinned(command, args):
    if command not in {"npx", "uvx", "pipx"}:
        return False
    if command == "pipx" and (not args or args[0] != "run"):
        return False
    if command == "npx" and not any(x in {"-y", "--yes"} for x in args):
        return False
    candidates = [x for x in args if not x.startswith("-") and x != "run"]
    if not candidates:
        return True
    package = candidates[0]
    if command == "npx":
        return re.search(r"@\d+\.\d+\.\d+(?:[-+][\w.-]+)?$", package) is None
    if command == "uvx" and re.search(r"@\d+(?:\.\d+)+(?:[\w.+-]*)$", package):
        return False
    return re.search(r"==\d+(?:\.\d+)+(?:[\w.+-]*)$", package) is None


def json_document(data):
    """Accept JSON and JSONC (VS Code comments/trailing commas), without eval."""
    text = data.decode("utf-8-sig")
    pattern = r'("(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/)'
    text = re.sub(pattern, lambda m: m.group() if m.group().startswith('"') else " ", text)
    text = re.sub(r'("(?:\\.|[^"\\])*"|,\s*(?=[}\]]))', lambda m: m.group() if m.group().startswith('"') else "", text)
    result = json.loads(text)
    if not isinstance(result, dict):
        raise SafeError("expected an object; not inspected")
    return result


def gh_document(data):
    """Restricted hosts.yml subset emitted by gh; no YAML object construction."""
    result = {}
    host = None
    for line in data.decode("utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([^\s:#]+):\s*", line)
        if match:
            host = match[1]
            result[host] = {"tokens": []}
            continue
        match = re.fullmatch(r"\s+([\w.-]+):\s*(.*?)\s*", line)
        if not host or not match:
            raise SafeError("unsupported gh YAML; not inspected")
        name, value = match.groups()
        if value.startswith('"'):
            value = json.loads(value)
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1].replace("''", "'")
        else:
            value = value.split(" #", 1)[0].strip()
            if value in {"|", ">"} or value.startswith(("&", "*", "!", "{")):
                raise SafeError("unsupported gh YAML; not inspected")
        if name == "oauth_token" and value:
            result[host]["tokens"].append(value)
        elif name == "user":
            result[host]["user"] = value
    return result


class Inventory:
    def __init__(self, home, config_home, cfg, key, known=(), now=None):
        self.home, self.config_home, self.cfg = home, config_home, cfg
        self.key, self.redactor = key, Redactor(key)
        self.now = now or datetime.now(timezone.utc)
        self.known = set(cfg.get("known_servers", [])) | set(known)
        self.entries, self.sources, self.findings = [], [], []
        self.env_paths = set(absolute(p) for p in cfg.get("env_files", []))
        self.seen = set()

    def finding(self, rule, entry, reason, severity="warn"):
        self.findings.append({"rule": rule, "severity": severity, "entry": entry["id"], "reason": reason})

    def record(self, collector, path, name, info, parent, kind="credential"):
        return {"id": fingerprint(self.key, json.dumps([collector, str(path), name])),
                "collector": collector, "source": str(path), "name": str(name), "kind": kind,
                "mode": format(stat.S_IMODE(info.st_mode), "04o"),
                "directory_mode": format(stat.S_IMODE(parent.st_mode), "04o"),
                "mtime_ns": info.st_mtime_ns, "credentials": [], "scopes": []}

    def credential(self, entry, value, inline=False):
        if isinstance(value, str) and value.lower().startswith("bearer "):
            value = value[7:].strip()
        fp = self.redactor.add(value)
        if fp and fp not in entry["credentials"]:
            entry["credentials"].append(fp)
        if fp and inline:
            entry["inline_secret"] = True

    def mcp(self, collector, path, doc, info, parent):
        containers = [("", doc)]
        projects = doc.get("projects", {})
        if isinstance(projects, dict):
            containers += [(str(name) + ":", val) for name, val in projects.items() if isinstance(val, dict)]
        for prefix, obj in containers:
            servers = obj.get("mcp_servers", obj.get("mcpServers", obj.get("servers", {})))
            if not isinstance(servers, dict):
                raise SafeError("invalid MCP server map; not inspected")
            for name, server in servers.items():
                if not isinstance(server, dict):
                    raise SafeError("invalid MCP server entry; not inspected")
                entry = self.record(collector, path, prefix + name, info, parent, "mcp")
                command, args, url = server.get("command", ""), server.get("args", []), server.get("url", server.get("serverUrl", ""))
                if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(x, str) for x in args) or not isinstance(url, str):
                    raise SafeError("invalid command, args or URL; not inspected")
                parsed = urlsplit(url)
                transport = server.get("type", server.get("transport", "http" if url else "stdio"))
                entry.update(transport=transport if transport in {"stdio", "http", "sse", "streamable-http"} else "unknown",
                             command=Path(command).name if command else "", url_host=parsed.hostname or "",
                             args_hmac=fingerprint(self.key, json.dumps(args)),
                             command_hmac=fingerprint(self.key, command),
                             args_shape=["reference" if not is_value(a) else "option" if a.startswith("-") else "url" if "://" in a else "value" for a in args],
                             inline_secret=False, env_names=[], enabled=server.get("enabled", True) is not False and server.get("disabled", False) is not True)
                env = server.get("env", {})
                if not isinstance(env, dict):
                    raise SafeError("invalid environment map; not inspected")
                entry["env_names"] = sorted(str(n) for n in env)
                for n, value in env.items():
                    if SECRET_NAME.search(n) or (isinstance(value, str) and TOKEN.search(value)):
                        self.credential(entry, value, True)
                for value in server.get("env_vars", []):
                    if isinstance(value, str):
                        entry["env_names"].append(value)
                for header_field in ("headers", "http_headers"):
                    headers = server.get(header_field, {})
                    if not isinstance(headers, dict):
                        raise SafeError("invalid header map; not inspected")
                    for value in headers.values():
                        self.credential(entry, value, True)
                env_headers = server.get("env_http_headers", {})
                if isinstance(env_headers, dict):
                    entry["env_names"] += [v for v in env_headers.values() if isinstance(v, str)]
                for field in ("bearer_token_env_var", "api_key_env"):
                    if isinstance(server.get(field), str):
                        entry["env_names"].append(server[field])
                for field, value in server.items():
                    if SECRET_NAME.search(field) and not field.endswith(("_env", "_env_var")):
                        self.credential(entry, value, True)
                for index, arg in enumerate(args):
                    for match in TOKEN.finditer(arg):
                        self.credential(entry, match.group(), True)
                    if "=" in arg:
                        option, value = arg.split("=", 1)
                        if SECRET_NAME.search(option):
                            self.credential(entry, value, True)
                    elif index and args[index - 1].startswith("-") and SECRET_NAME.search(args[index - 1]):
                        self.credential(entry, arg, True)
                    header = re.fullmatch(r"(?i)(?:authorization|x-api-key)\s*:\s*(.+)", arg)
                    if header:
                        self.credential(entry, header[1], True)
                    if "://" in arg:
                        self.url_credentials(entry, arg)
                self.url_credentials(entry, url)
                self.env_references(path, server, args)
                entry["env_names"] = sorted(set(entry["env_names"]))
                entry["scopes"] = scopes(server.get("scopes", server.get("scope", [])))
                entry["launch_unpinned"] = unpinned(entry["command"], args)
                # Exists/access checks only. Never execute the command.
                if command:
                    expanded = os.path.expanduser(command)
                    candidate = absolute(path.parent / expanded) if "/" in expanded and not os.path.isabs(expanded) else expanded
                    entry["command_missing"] = not (os.path.isfile(candidate) and os.access(candidate, os.X_OK)) if "/" in expanded else shutil.which(command) is None
                else:
                    entry["command_missing"] = not bool(url)
                entry["known"] = name in self.known or (prefix + name) in self.known
                self.entries.append(entry)

    def url_credentials(self, entry, url):
        parsed = urlsplit(url)
        for value in (parsed.username, parsed.password):
            if value:
                self.credential(entry, unquote(value), True)
        for name, value in parse_qsl(parsed.query):
            if SECRET_NAME.search(name):
                self.credential(entry, value, True)
        if parsed.hostname == "hooks.slack.com" and parsed.path:
            self.credential(entry, url, True)

    def env_references(self, path, server, args):
        refs = []
        for field in ("envFile", "env_file", "envFiles", "env_files"):
            value = server.get(field, [])
            refs.extend([value] if isinstance(value, str) else value if isinstance(value, list) else [])
        for index, arg in enumerate(args):
            if arg.startswith("--env-file="):
                refs.append(arg.split("=", 1)[1])
            elif index and args[index - 1] in {"--env-file", "--envfile"}:
                refs.append(arg)
        for ref in refs:
            if isinstance(ref, str) and "$" not in ref:
                expanded = Path(os.path.expanduser(ref))
                self.env_paths.add(absolute(expanded if expanded.is_absolute() else path.parent / expanded))

    def auth(self, collector, path, doc, info, parent):
        entry = self.record(collector, path, "authentication", info, parent)
        mode = doc.get("auth_mode", "unknown")
        entry["auth_type"] = mode if mode in {"chatgpt", "apikey", "api_key"} else "unknown"
        def walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if SECRET_NAME.search(k):
                        self.credential(entry, v)
                    walk(v)
            elif isinstance(obj, list):
                for v in obj:
                    walk(v)
        walk(doc)
        self.entries.append(entry)

    def gh(self, path, doc, info, parent):
        for host, item in doc.items():
            entry = self.record("gh", path, host, info, parent)
            entry.update(host=host, user=item.get("user", "unknown"), token_storage="inline" if item["tokens"] else "keyring-or-absent: not inspected", scope_visibility="unknown offline")
            for token in item["tokens"]:
                self.credential(entry, token)
            self.entries.append(entry)

    def rclone(self, path, raw, info, parent):
        if raw.lstrip().startswith(b"RCLONE_ENCRYPT_V"):
            self.sources[-1]["status"] = "encrypted: not inspected"
            entry = self.record("rclone", path, "encrypted configuration", info, parent)
            entry["token_storage"] = "encrypted: not inspected"
            self.entries.append(entry)
            return
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(raw.decode("utf-8"))
        for name in parser.sections():
            item = dict(parser[name])
            self.redactor.discover(item)
            entry = self.record("rclone", path, name, info, parent)
            entry.update(remote_type=item.get("type", "unknown"), scopes=scopes(item.get("scope", "")))
            if "drive_type" in item:
                entry["drive_type"] = item["drive_type"]
            for key, value in item.items():
                if SECRET_NAME.search(key) and key != "token":
                    self.credential(entry, value)
            if item.get("token"):
                token = json.loads(item["token"])
                if not isinstance(token, dict):
                    raise SafeError("invalid rclone token JSON; not inspected")
                for key in ("access_token", "refresh_token", "id_token"):
                    self.credential(entry, token.get(key))
                if "expiry" in token:
                    # Validate before retaining even a purported timestamp.
                    entry["expiry"] = datetime.fromisoformat(str(token["expiry"]).replace("Z", "+00:00")).isoformat()
            self.entries.append(entry)

    def env(self, path, raw, info, parent):
        for line in raw.decode("utf-8").splitlines():
            match = re.match(r"^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)$", line)
            if not match or not SECRET_NAME.search(match[1]):
                continue
            name, value = match.groups()
            value = value.strip()
            if value.startswith(('"', "'")) and not value.endswith(value[:1]):
                raise SafeError("multiline environment value; not inspected")
            if value.startswith(('"', "'")) and value.endswith(value[:1]):
                value = value[1:-1]
            else:
                value = value.split(" #", 1)[0].strip()
            entry = self.record("env", path, name, info, parent)
            entry["env_names"] = [name]
            self.credential(entry, value)
            self.entries.append(entry)

    def manual(self, path, doc, info, parent):
        items = doc.get("connectors", [])
        if not isinstance(items, list):
            raise SafeError("manual connectors must be an array of tables")
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise SafeError("invalid manual connector")
            entry = self.record("manual", path, item["name"], info, parent, "manual")
            entry.update(scopes=scopes(item.get("scopes", [])), scope_visibility="declared, not verified", token_storage="off-box: not inspected")
            if item.get("review_by"):
                entry["review_by"] = datetime.fromisoformat(str(item["review_by"])).date().isoformat()
            else:
                entry["review_by"] = None
            self.entries.append(entry)

    def read(self, collector, path, required=False):
        path = absolute(path)
        if (collector, path) in self.seen:
            return
        self.seen.add((collector, path))
        source = {"collector": collector, "path": str(path), "status": "missing", "required": required}
        self.sources.append(source)
        start = len(self.entries)
        try:
            raw, info, parent = bounded_read(path, self.home)
            source.update(mode=format(stat.S_IMODE(info.st_mode), "04o"), status="read")
            if collector == "rclone":
                self.rclone(path, raw, info, parent)
                return
            if collector == "env":
                self.env(path, raw, info, parent)
                return
            if collector == "gh":
                doc = gh_document(raw)
                self.redactor.discover(doc)
                self.gh(path, doc, info, parent)
                return
            doc = tomllib.loads(raw.decode("utf-8")) if path.suffix == ".toml" else json_document(raw)
            self.redactor.discover(doc)
            if collector == "manual":
                self.manual(path, doc, info, parent)
            elif collector == "codex-auth":
                self.auth(collector, path, doc, info, parent)
            else:
                self.mcp(collector, path, doc, info, parent)
        except FileNotFoundError:
            source["status"] = "missing"
            del self.entries[start:]
        except (OSError, ValueError, TypeError, KeyError, AttributeError, SafeError, configparser.Error, RecursionError) as exc:
            source["status"] = read_error(exc)
            del self.entries[start:]

    def collect(self, roots=()):
        home, config = self.home, self.config_home
        defaults = [("cursor", home / ".cursor/mcp.json"), ("codex", home / ".codex/config.toml"),
                    ("codex-auth", home / ".codex/auth.json"), ("claude", home / ".claude.json"),
                    ("claude", config / "Claude/claude_desktop_config.json"), ("vscode", config / "Code/User/mcp.json"),
                    ("other", home / ".codeium/windsurf/mcp_config.json"), ("other", home / ".gemini/settings.json"),
                    ("gh", absolute(os.environ.get("GH_CONFIG_DIR", config / "gh")) / "hosts.yml"),
                    ("rclone", absolute(os.environ.get("RCLONE_CONFIG", config / "rclone/rclone.conf"))),
                    ("manual", config / "reachward/cloud_connectors.toml")]
        for root in list(roots) + self.cfg.get("roots", []):
            for collector, suffix in (("cursor", ".cursor/mcp.json"), ("claude", ".mcp.json"), ("vscode", ".vscode/mcp.json")):
                defaults.append((collector, absolute(root) / suffix))
        for collector, path in defaults:
            self.read(collector, path)
        for item in self.cfg.get("extra_sources", []):
            self.read(item.get("collector", "other"), item["path"], required=True)
        for path in sorted(self.env_paths):
            self.read("env", path, required=True)
        return self
