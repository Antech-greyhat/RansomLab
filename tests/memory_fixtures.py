"""Test-only fixture adapter: bytes never leave memory; SQLite is separate.

Directory scaffolding in a TemporaryDirectory is ordinary generated test data.
No encrypted or modified working fixture is written to the host filesystem.
This adapter is never imported by the application or selected by its CLI.
"""
from contextlib import contextmanager
from pathlib import Path
import threading

from ransomlab.core.errors import SafetyError, StateError


class MemoryDirectory:
    entries = {}
    serial = 0

    def __init__(self, path, create=False):
        self.path = Path(path)
        self.key = str(self.path)
        if create:
            self.path.mkdir(parents=False, exist_ok=False)
            self.entries[self.key] = {}
        if self.key not in self.entries:
            raise SafetyError("Unknown in-memory fixture directory")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def create(self, name, data):
        if name in self.entries[self.key]:
            raise SafetyError("Memory fixture already exists")
        type(self).serial += 1
        self.entries[self.key][name] = [bytes(data), {"device": 1, "inode": type(self).serial}]
        return self.identity(name)

    def read(self, name, max_bytes):
        try:
            value = self.entries[self.key][name][0]
        except KeyError:
            raise SafetyError("Missing in-memory fixture") from None
        if len(value) > max_bytes:
            raise SafetyError("Memory fixture byte ceiling exceeded")
        return value

    def identity(self, name):
        return dict(self.entries[self.key][name][1])

    def replace(self, name, data, expected=None):
        if expected is not None and self.identity(name) != expected:
            raise SafetyError("Memory fixture identity mismatch")
        self.entries[self.key][name][0] = bytes(data)
        return self.identity(name)

    def names(self):
        return list(self.entries[self.key])

    def exists(self, name):
        return name in self.entries[self.key]

    @contextmanager
    def pin(self, name):
        yield


class MemoryLease:
    locks = {}

    def __init__(self, path):
        self.lock = self.locks.setdefault(str(path), threading.Lock())

    def __enter__(self):
        if not self.lock.acquire(blocking=False):
            raise StateError("A mutator already owns this test lab")
        return self

    def __exit__(self, *args):
        self.lock.release()
