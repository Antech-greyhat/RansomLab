"""Public error categories with safe, caller-facing messages."""


class LabError(Exception):
    """Base class for expected application failures."""


class ValidationError(LabError):
    """Input failed a closed, bounded contract."""


class SafetyError(LabError):
    """An operation cannot establish its required safety boundary."""


class StateError(LabError):
    """Application state or durable storage cannot support an operation."""


class DependencyError(LabError):
    """A separately approved runtime capability is unavailable."""

