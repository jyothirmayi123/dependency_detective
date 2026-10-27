"""Input and file validation. Raises ValueError with a user-friendly message."""
from pathlib import Path

from backend.config import MAX_UPLOAD_BYTES
from backend.parsers import FORMATS, SUPPORTED_EXT


def validate_text(text: str) -> str:
    if not text or not text.strip():
        raise ValueError("The input is empty. Paste a dependency file or upload one.")
    if "\x00" in text:
        raise ValueError("This looks like a binary file, not a text dependency file.")
    if len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise ValueError(f"Input is too large (limit {MAX_UPLOAD_BYTES // 1024} KB).")
    return text


def validate_upload(name: str, data: bytes) -> str:
    low = Path(name).name.lower()
    if not low.endswith(tuple("." + e for e in SUPPORTED_EXT)):
        raise ValueError(f"Unsupported file type '{name}'. Supported formats: " + ", ".join(FORMATS))
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError(f"'{name}' is too large (limit {MAX_UPLOAD_BYTES // 1024} KB).")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError(f"'{name}' must be UTF-8 text.")
    return validate_text(text)
