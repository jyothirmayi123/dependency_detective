"""Backward-compatible shim: the requirements.txt parser now lives in backend.parsers.python."""
from backend.parsers.python import parse_requirements  # noqa: F401
