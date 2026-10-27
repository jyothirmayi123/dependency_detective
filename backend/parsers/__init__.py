"""Manifest/lockfile parser registry: detect the format, then parse it into dependency entries."""
import json
import re
from pathlib import Path

from backend.parsers.cpp import parse_conan_lock, parse_conanfile_txt
from backend.parsers.dotnet import parse_csproj, parse_packages_config
from backend.parsers.go import parse_go_mod
from backend.parsers.java import parse_gradle, parse_pom
from backend.parsers.javascript import parse_package_json, parse_package_lock
from backend.parsers.php import parse_composer_json, parse_composer_lock
from backend.parsers.python import parse_pipfile_lock, parse_poetry_lock, parse_requirements
from backend.parsers.ruby import parse_gemfile_lock
from backend.parsers.rust import parse_cargo_lock, parse_cargo_toml

# format id -> (ecosystem, parser, "lock"=exact versions + dependency tree / "manifest"=declared versions)
FORMATS = {
    "requirements.txt":  ("PyPI", parse_requirements, "manifest"),
    "poetry.lock":       ("PyPI", parse_poetry_lock, "lock"),
    "Pipfile.lock":      ("PyPI", parse_pipfile_lock, "lock"),
    "package.json":      ("npm", parse_package_json, "manifest"),
    "package-lock.json": ("npm", parse_package_lock, "lock"),
    "pom.xml":           ("Maven", parse_pom, "manifest"),
    "build.gradle":      ("Maven", parse_gradle, "manifest"),
    "conanfile.txt":     ("ConanCenter", parse_conanfile_txt, "manifest"),
    "conan.lock":        ("ConanCenter", parse_conan_lock, "lock"),
    "go.mod":            ("Go", parse_go_mod, "manifest"),
    "Cargo.toml":        ("crates.io", parse_cargo_toml, "manifest"),
    "Cargo.lock":        ("crates.io", parse_cargo_lock, "lock"),
    "Gemfile.lock":      ("RubyGems", parse_gemfile_lock, "lock"),
    "composer.json":     ("Packagist", parse_composer_json, "manifest"),
    "composer.lock":     ("Packagist", parse_composer_lock, "lock"),
    "*.csproj":          ("NuGet", parse_csproj, "manifest"),
    "packages.config":   ("NuGet", parse_packages_config, "manifest"),
}
SUPPORTED_EXT = ["txt", "json", "lock", "xml", "gradle", "kts", "toml", "mod", "csproj", "fsproj", "vbproj", "config", "props"]
_EXACT = {k.lower(): k for k in FORMATS if not k.startswith("*")}
_EXACT["directory.packages.props"] = "*.csproj"


def _sniff(text: str) -> str | None:
    t = text.lstrip()
    if t.startswith("{"):
        try:
            d = json.loads(t)
        except json.JSONDecodeError:
            return None
        if not isinstance(d, dict):
            return None
        if "lockfileVersion" in d:
            return "package-lock.json"
        if "content-hash" in d and ("packages" in d or "packages-dev" in d):
            return "composer.lock"
        if "_meta" in d and "default" in d:
            return "Pipfile.lock"
        if "requires" in d and ("version" in d or "build_requires" in d) or "graph_lock" in d:
            return "conan.lock"
        if {"dependencies", "devDependencies"} & set(d):
            return "package.json"
        if {"require", "require-dev"} & set(d):
            return "composer.json"
    if t.startswith("<"):
        if re.search(r"<project[\s>]", t, re.I) and "<modelVersion" in t or "maven.apache.org" in t:
            return "pom.xml"
        if re.search(r"<Project[\s>]", t):
            return "*.csproj"
        if re.search(r"<packages[\s>]", t):
            return "packages.config"
    if re.search(r"^module\s+\S+", t, re.M) and re.search(r"^go\s+\d", t, re.M):
        return "go.mod"
    if "[requires]" in t:
        return "conanfile.txt"
    if re.search(r"^GEM\s*$", t, re.M) and "remote:" in t:
        return "Gemfile.lock"
    if "[[package]]" in t:
        return "poetry.lock" if ("content-hash" in t or "[metadata]" in t) else "Cargo.lock"
    if re.search(r"^\s*\[(dependencies|dev-dependencies)\]", t, re.M):
        return "Cargo.toml"
    return None


def detect_format(filename: str, text: str = "") -> str:
    low = Path(filename or "").name.lower()
    if low in _EXACT:
        return _EXACT[low]
    if low.endswith((".csproj", ".fsproj", ".vbproj")):
        return "*.csproj"
    if low.endswith((".gradle", ".gradle.kts")):
        return "build.gradle"
    if low.endswith(".txt") and "[requires]" not in text:
        return "requirements.txt"
    fmt = _sniff(text)
    if fmt:
        return fmt
    raise ValueError(f"Could not recognise '{filename}'. Supported: " + ", ".join(FORMATS))


def parse_manifest(filename: str, text: str, fmt: str | None = None):
    """Return (format_id, entries). Raises ValueError with a friendly message on bad input."""
    fmt = fmt or detect_format(filename, text)
    try:
        return fmt, FORMATS[fmt][1](text)
    except ValueError as ex:
        raise ValueError(f"{filename}: {ex}")
