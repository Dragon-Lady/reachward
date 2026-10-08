import os
from pathlib import Path
import stat
try:
    import tomllib
except ImportError:  # Python 3.10 only
    import tomli as tomllib

from .safety import absolute, bounded_read, SafeError


def locations():
    home = absolute(Path.home())
    config = absolute(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
    state = absolute(os.environ.get("XDG_STATE_HOME", home / ".local/state"))
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
    return cfg
