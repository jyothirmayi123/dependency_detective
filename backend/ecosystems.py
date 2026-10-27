"""Supported ecosystems: OSV name, display label, name normalisation and package URLs (purl)."""
from urllib.parse import quote

from packaging.utils import canonicalize_name

# key = OSV ecosystem name (used in advisory data and in the OSV API)
ECOSYSTEMS = {
    "PyPI":        {"label": "Python",            "purl": "pypi"},
    "npm":         {"label": "JavaScript / Node", "purl": "npm"},
    "Maven":       {"label": "Java (Maven/Gradle)", "purl": "maven"},
    "ConanCenter": {"label": "C / C++ (Conan)",   "purl": "conan"},
    "Go":          {"label": "Go",                "purl": "golang"},
    "crates.io":   {"label": "Rust",              "purl": "cargo"},
    "RubyGems":    {"label": "Ruby",              "purl": "gem"},
    "Packagist":   {"label": "PHP",               "purl": "composer"},
    "NuGet":       {"label": ".NET (C#)",         "purl": "nuget"},
}


def label(eco: str) -> str:
    return ECOSYSTEMS.get(eco, {}).get("label", eco)


def normalize_name(eco: str, name: str) -> str:
    """Canonical form used to compare package names within one ecosystem."""
    if eco == "PyPI":
        return canonicalize_name(name)
    if eco in ("npm", "Packagist", "NuGet", "ConanCenter", "crates.io"):
        return name.lower()
    return name  # Maven, Go, RubyGems are case-sensitive in practice


def purl(eco: str, name: str, version: str | None) -> str:
    kind = ECOSYSTEMS.get(eco, {}).get("purl", eco.lower())
    if eco == "Maven" and ":" in name:
        group, art = name.split(":", 1)
        path = f"{quote(group, safe='')}/{quote(art, safe='')}"
    else:
        path = quote(name, safe="/")  # '@scope/name' -> '%40scope/name'
    out = f"pkg:{kind}/{path}"
    return f"{out}@{quote(version, safe='')}" if version else out


def package_download_url(eco: str, name: str, version: str) -> str | None:
    """Return a direct archive download URL when the registry has a stable format."""
    ver = quote(version, safe="")
    if eco == "PyPI":
        # PyPI file URLs include content hashes, so keep verified wheel/source links
        # for the bundled demo's suggested releases instead of guessing a URL.
        files = {
            ("pyyaml", "5.4"): "https://files.pythonhosted.org/packages/b5/fd/15638de2da0a5aa91c095718444624aa565f766fc178249ca6faa372f71a/PyYAML-5.4.tar.gz",
            ("flask", "2.2.5"): "https://files.pythonhosted.org/packages/5f/76/a4d2c4436dda4b0a12c71e075c508ea7988a1066b06a575f6afe4fecc023/Flask-2.2.5.tar.gz",
            ("urllib3", "1.26.17"): "https://files.pythonhosted.org/packages/dd/19/9e5c8b813a8bddbfb035fa2b0c29077836ae7c4def1a55ae4632167b3511/urllib3-1.26.17.tar.gz",
            ("pillow", "10.0.1"): "https://files.pythonhosted.org/packages/64/9e/7e638579cce7dc346632f020914141a164a872be813481f058883ee8d421/Pillow-10.0.1.tar.gz",
            ("requests", "2.31.0"): "https://files.pythonhosted.org/packages/9d/be/10918a2eac4ae9f02f6cfe6414b7a155ccd8f7f9d4380d62fd5b955065c3/requests-2.31.0.tar.gz",
            ("jinja2", "3.1.3"): "https://files.pythonhosted.org/packages/b2/5e/3a21abf3cd467d7876045335e681d276ac32492febe6d98ad89562d1a7e1/Jinja2-3.1.3.tar.gz",
        }
        return files.get((canonicalize_name(name), version))
    if eco == "Maven" and ":" in name:
        group, artifact = name.split(":", 1)
        path = "/".join(quote(part, safe="") for part in group.split("."))
        path += f"/{quote(artifact, safe='')}/{ver}/{quote(artifact, safe='')}-{ver}.jar"
        return f"https://repo.maven.apache.org/maven2/{path}"
    if eco == "ConanCenter":
        archives = {
            ("zlib", "1.2.13"): "https://zlib.net/fossils/zlib-1.2.13.tar.gz",
            ("openssl", "1.1.1n"): "https://www.openssl.org/source/old/1.1.1/openssl-1.1.1n.tar.gz",
        }
        return archives.get((name.lower(), version))
    if eco == "npm":
        package = quote(name, safe="/@")
        artifact = quote(name.rsplit("/", 1)[-1], safe="")
        return f"https://registry.npmjs.org/{package}/-/{artifact}-{ver}.tgz"
    if eco == "Go":
        module = "".join(f"!{char.lower()}" if char.isupper() else char for char in name)
        module = quote(module, safe="/!")
        return f"https://proxy.golang.org/{module}/@v/v{ver}.zip"
    if eco == "crates.io":
        package = quote(name, safe="")
        return f"https://crates.io/api/v1/crates/{package}/{ver}/download"
    if eco == "RubyGems":
        package = quote(name, safe="")
        return f"https://rubygems.org/downloads/{package}-{ver}.gem"
    if eco == "NuGet":
        package = quote(name, safe="")
        return f"https://www.nuget.org/api/v2/package/{package}/{ver}"
    return None
