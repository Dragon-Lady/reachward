import os
from pathlib import Path
import pytest


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(path / ".config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(path / ".local/state"))
    for name in ("RCLONE_CONFIG", "GH_CONFIG_DIR", "GH_HOST", "GH_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    return path


@pytest.fixture
def put(home):
    def write(relative, text, mode=0o600):
        target = home / relative
        missing = []
        parent = target.parent
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for path in reversed(missing):
            path.mkdir(mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
        return target
    return write
