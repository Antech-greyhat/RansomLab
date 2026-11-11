"""Structured diagnostics; SQLite remains the authoritative audit journal."""
import json
import logging
import sys

from .events import Event, utc_now

LOGGER = logging.getLogger("ransomlab.audit")


class EventFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = record.msg if isinstance(record.msg, Event) else None
        return json.dumps({"timestamp": utc_now(), "level": record.levelname,
                           "event": event.to_dict() if event else None},
                          sort_keys=True, allow_nan=False)


def configure_logging(level: str = "WARNING") -> None:
    """Configure only the application logger; never change root handlers."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(EventFormatter())
    for previous in list(LOGGER.handlers):
        LOGGER.removeHandler(previous)
        previous.close()
    LOGGER.addHandler(handler)
    LOGGER.setLevel(level)
    LOGGER.propagate = False
