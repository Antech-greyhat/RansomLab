"""Local SQLite event authority with atomic event/state transactions.

The caller owns filesystem authorization and process-level fixture exclusion.
This repository never claims that its database transaction is atomic with a
fixture mutation. Durable intents and reconciliation belong to the service.
"""

import json
import math
import re
import sqlite3
from dataclasses import replace
from pathlib import Path

from .config import Policy
from .errors import StateError, ValidationError
from .events import Event, validate_id
from .logging import LOGGER

_STATE_KEY = re.compile(r"[a-z][a-z0-9_.:-]{0,127}\Z")
_MAX_STATE_BYTES = 1_048_576


def _state_key(key):
    if type(key) is not str or _STATE_KEY.fullmatch(key) is None:
        raise ValidationError("state key is outside the internal identifier contract")
    return key


def _check_json(value, depth=0, budget=None):
    """Bound serialization work before handing internal metadata to JSON."""
    if budget is None:
        budget = [20_000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 16:
        raise ValidationError("state value exceeds structural limits")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > 9_223_372_036_854_775_807:
            raise ValidationError("state integer exceeds supported bounds")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValidationError("state numbers must be finite")
        return
    if type(value) is str:
        if len(value) > 65_536:
            raise ValidationError("state text exceeds supported bounds")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or not 1 <= len(key) <= 256:
                raise ValidationError("state field names are invalid")
            _check_json(item, depth + 1, budget)
        return
    if type(value) is list:
        for item in value:
            _check_json(item, depth + 1, budget)
        return
    raise ValidationError("state value contains an unsupported data type")


def _state_json(value):
    _check_json(value)
    try:
        serialized = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)
        size = len(serialized.encode("utf-8"))
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ValidationError("state value cannot be serialized safely") from None
    if size > _MAX_STATE_BYTES:
        raise ValidationError("state value exceeds its serialized byte ceiling")
    return serialized


def _decode_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate stored field")
            result[key] = value
        return result

    def nonfinite(_):
        raise ValueError("non-finite stored value")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)


class EventStore:
    """Bounded per-lab journal, intended for one short-lived service call.

    Opening a read-only store uses SQLite's actual ``mode=ro`` and does not
    create a missing database. Callers should open separate connections in
    different threads and keep a store in a ``with`` block.
    """

    def __init__(self, path, readonly=False, policy=None):
        if type(readonly) is not bool:
            raise ValidationError("readonly must be a boolean")
        if policy is None:
            policy = Policy()
        if not isinstance(policy, Policy):
            raise ValidationError("repository requires a validated resource policy")
        try:
            self.path = Path(path).absolute()
        except (TypeError, ValueError):
            raise ValidationError("repository path is invalid") from None
        self.readonly = readonly
        self.policy = policy
        self._connection = None
        try:
            if self.path.exists() and self.path.stat().st_size > policy.max_database_bytes:
                raise StateError("database exceeds its storage ceiling")
            mode = "ro" if readonly else "rwc"
            connection = sqlite3.connect(self.path.as_uri() + "?mode=" + mode,
                                         uri=True, timeout=1.0, isolation_level=None)
            self._connection = connection
            connection.execute("PRAGMA busy_timeout = 1000")
            connection.execute("PRAGMA trusted_schema = OFF")
            if readonly:
                connection.execute("PRAGMA query_only = ON")
            else:
                connection.execute("PRAGMA journal_mode = DELETE")
                connection.execute("PRAGMA synchronous = FULL")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0 and not readonly:
                tables = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
                if tables:
                    raise StateError("unversioned existing database is not a RansomLab store")
                self._set_page_limit()
                self._initialize()
            elif version != 1:
                raise StateError("database schema version is unsupported")
            self._validate_schema()
            if not readonly:
                self._set_page_limit()
            pages = connection.execute("PRAGMA page_count").fetchone()[0]
            page_size = connection.execute("PRAGMA page_size").fetchone()[0]
            if pages * page_size > policy.max_database_bytes:
                raise StateError("database exceeds its storage ceiling")
        except StateError:
            self.close()
            raise
        except (sqlite3.Error, OSError, ValueError):
            self.close()
            raise StateError("event store could not be opened or validated") from None

    def _db(self):
        if self._connection is None:
            raise StateError("event store is closed")
        return self._connection

    def _set_page_limit(self):
        db = self._db()
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        pages = self.policy.max_database_bytes // page_size
        if pages < 1:
            raise StateError("database limit cannot fit a storage page")
        # Integer is validated locally; PRAGMA does not accept placeholders.
        actual = db.execute(f"PRAGMA max_page_count = {pages:d}").fetchone()[0]
        if actual > pages:
            raise StateError("existing database exceeds its page ceiling")

    def _initialize(self):
        db = self._db()
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, run_id TEXT, json TEXT NOT NULL)")
            db.execute("CREATE INDEX event_run_sequence ON events (run_id, seq)")
            db.execute("CREATE TABLE state (key TEXT PRIMARY KEY, json TEXT NOT NULL)")
            db.execute("PRAGMA user_version = 1")
            db.commit()
        except sqlite3.Error:
            db.rollback()
            raise

    def _validate_schema(self):
        db = self._db()
        events = [(row[1], row[2], row[5]) for row in db.execute("PRAGMA table_info(events)")]
        state = [(row[1], row[2], row[5]) for row in db.execute("PRAGMA table_info(state)")]
        if events != [("seq", "INTEGER", 1), ("id", "TEXT", 0), ("run_id", "TEXT", 0), ("json", "TEXT", 0)] or state != [("key", "TEXT", 1), ("json", "TEXT", 0)]:
            raise StateError("database tables do not match the supported schema")

    def append(self, event, updates=None, expected=None):
        if self.readonly:
            raise StateError("read-only event store cannot accept mutations")
        if not isinstance(event, Event) or event.sequence is not None:
            raise ValidationError("append requires an unsequenced validated event")
        if updates is None:
            updates = {}
        if type(updates) is not dict or len(updates) > 32:
            raise ValidationError("state updates must be a bounded mapping")
        serialized_updates = [(_state_key(key), _state_json(value)) for key, value in updates.items()]
        if expected is None:
            expected = {}
        if type(expected) is not dict or len(expected) > 32:
            raise ValidationError("expected state must be a bounded mapping")
        serialized_expected = [(_state_key(key), _state_json(value)) for key, value in expected.items()]
        raw = event.to_json()
        if len(raw.encode("utf-8")) > self.policy.max_event_bytes:
            raise ValidationError("event exceeds the configured byte ceiling")
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            for key, value in serialized_expected:
                row = db.execute("SELECT json FROM state WHERE key = ?", (key,)).fetchone()
                if (row[0] if row else "null") != value:
                    raise StateError("Control state changed before the operation could start")
            if db.execute("SELECT COUNT(*) FROM events").fetchone()[0] >= self.policy.max_events:
                raise StateError("event count ceiling reached")
            cursor = db.execute("INSERT INTO events (id, run_id, json) VALUES (?, ?, ?)", (event.id, event.run_id, raw))
            sequenced = replace(event, sequence=cursor.lastrowid)
            raw = sequenced.to_json()
            if len(raw.encode("utf-8")) > self.policy.max_event_bytes:
                raise StateError("sequenced event exceeds its configured byte ceiling")
            db.execute("UPDATE events SET json = ? WHERE seq = ?", (raw, sequenced.sequence))
            for key, value in serialized_updates:
                db.execute("INSERT INTO state (key, json) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET json=excluded.json", (key, value))
            db.commit()
            LOGGER.info(sequenced)
            return sequenced
        except (StateError, ValidationError):
            self._rollback()
            raise
        except sqlite3.Error:
            self._rollback()
            raise StateError("event transaction failed; no new operation may be assumed recorded") from None

    def _rollback(self):
        try:
            self._db().rollback()
        except sqlite3.Error:
            self.close()
            raise StateError("event transaction failed and the connection could not be recovered") from None

    def get_state(self, key, default=None):
        key = _state_key(key)
        try:
            row = self._db().execute("SELECT json FROM state WHERE key = ?", (key,)).fetchone()
            if row is None:
                return default
            if type(row[0]) is not str or len(row[0].encode("utf-8")) > _MAX_STATE_BYTES:
                raise StateError("stored state exceeds its schema limits")
            value = _decode_json(row[0])
            _check_json(value)
            return value
        except (sqlite3.Error, ValueError, UnicodeError, RecursionError, ValidationError):
            raise StateError("stored state could not be read or validated") from None

    def events(self, limit=200, after=0, run_id=None):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValidationError("event query limit must be between 1 and 1000")
        if type(after) is not int or not 0 <= after <= 9_223_372_036_854_775_807:
            raise ValidationError("event cursor must be a non-negative storage integer")
        if run_id is not None:
            validate_id(run_id)
        try:
            if run_id is None:
                rows = self._db().execute("SELECT seq, id, run_id, json FROM events WHERE seq > ? ORDER BY seq LIMIT ?", (after, limit)).fetchall()
            else:
                rows = self._db().execute("SELECT seq, id, run_id, json FROM events WHERE seq > ? AND run_id = ? ORDER BY seq LIMIT ?", (after, run_id, limit)).fetchall()
            results = []
            for seq, identifier, stored_run_id, raw in rows:
                if type(raw) is not str or len(raw.encode("utf-8")) > self.policy.max_event_bytes:
                    raise StateError("stored event exceeds its schema limits")
                event = Event.from_dict(_decode_json(raw))
                if event.sequence != seq or event.id != identifier or event.run_id != stored_run_id:
                    raise StateError("event columns and payload are inconsistent")
                results.append(event)
            return results
        except (sqlite3.Error, ValueError, UnicodeError, RecursionError, ValidationError):
            raise StateError("event history could not be read or validated") from None

    def count(self):
        try:
            return self._db().execute("SELECT COUNT(*) FROM events").fetchone()[0]
        except sqlite3.Error:
            raise StateError("event count could not be read") from None

    def close(self):
        if self._connection is not None:
            connection, self._connection = self._connection, None
            connection.close()

    def __enter__(self):
        self._db()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

