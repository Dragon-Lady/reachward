import os
from pathlib import Path
import stat
try:
    import tomllib
except ImportError:  # Python 3.10 only
    import tomli as tomllib

from .safety import absolute, bounded_read, SafeError

DEFAULT_COMMAND_SEARCH_PATH = ["~/.local/bin", "/usr/local/bin", "/usr/bin", "/bin"]


def home_path(path, home):
    """Normalize only the selected HOME alias, never resolve source symlinks."""
    path, alias = absolute(path), absolute(Path.home())
    return home / path.relative_to(alias) if path.is_relative_to(alias) else path


def command_search_path(cfg, home):
    values = cfg.get("command_search_path", DEFAULT_COMMAND_SEARCH_PATH)
    if not isinstance(values, list) or not values or any(
        not isinstance(v, str) or not v or (not v.startswith(("/", "~/")))
        or ":" in v or any(ord(c) < 32 or ord(c) == 127 for c in v) for v in values
    ):
        raise SafeError("command_search_path must contain absolute or ~/ directories without colons or controls")
    return os.pathsep.join(str(home_path(v, home)) for v in values)


def locations():
    home = absolute(Path.home()).resolve(strict=True)
    config = home_path(os.environ.get("XDG_CONFIG_HOME", home / ".config"), home)
    state = home_path(os.environ.get("XDG_STATE_HOME", home / ".local/state"), home)
    return home, config, state


def load_config(path):
    try:
        raw, info, _ = bounded_read(path)
    except FileNotFoundError:
        return {}
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
        raise SafeError("Reach Ward config must be owned by this user and mode 0600")
    cfg = tomllib.loads(raw.decode("utf-8"))
    for name in ("known_servers", "env_files", "roots", "alert_channels"):
        if name in cfg and (not isinstance(cfg[name], list) or not all(isinstance(v, str) for v in cfg[name])):
            raise SafeError("invalid list in configuration")
    days = cfg.get("stale_days", 90)
    if type(days) is not int or days < 1:
        raise SafeError("stale_days must be a positive integer")
    extras = cfg.get("extra_sources", [])
    if not isinstance(extras, list) or any(not isinstance(v, dict) or not isinstance(v.get("path"), str) or v.get("collector", "other") not in {"cursor", "codex", "claude", "vscode", "other"} for v in extras):
        raise SafeError("invalid extra_sources configuration")
    if "alert_slack_webhook" in cfg:
        raise SafeError("use alert_slack_webhook_env; inline webhook URLs are not accepted")
    command_search_path(cfg, absolute(Path.home()))
    return cfg
