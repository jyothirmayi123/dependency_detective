"""Recommend an upgrade ONLY when advisory data supports it, and say how to apply it."""
from backend.core.matcher import affected_entries, fixes_for, version_affected
from backend.versioning import change_type, parse_version

CAVEAT = "Not checked against advisories outside this scan: re-scan after upgrading and run your tests."


def recommend(name: str, version: str, vulns: list[dict], ecosystem: str = "PyPI") -> dict:
    if not vulns:
        return {"version": None, "note": "", "change": None}
    key = lambda s: parse_version(ecosystem, s)
    targets = []
    for v in vulns:
        fixes = fixes_for(v, name, version, ecosystem)
        if not fixes:
            return {"version": None, "change": None,
                    "note": "At least one advisory lists no fixed version: no verified upgrade."}
        targets.append(min(fixes, key=key))
    target = max(targets, key=key)
    still = [v["id"] for v in vulns
             if any(version_affected(target, a, ecosystem) for a in affected_entries(v, name, ecosystem))]
    if still:
        return {"version": None, "change": None, "note": f"{target} is still listed as affected by {', '.join(still)}."}
    change = change_type(ecosystem, version, target)
    major = " Major version change: read the changelog." if change == "major" else ""
    return {"version": str(target), "change": change,
            "note": f"Fixes all advisories found for this version.{major} {CAVEAT}"}


def upgrade_command(eco: str, name: str, target: str, direct: bool | None) -> str:
    """A concrete, copy-paste hint for applying the upgrade in each ecosystem."""
    if eco == "PyPI":
        return f'pip install "{name}=={target}"   # and update your requirements/lock file'
    if eco == "npm":
        return (f'npm install {name}@{target}' if direct is not False
                else f'add to package.json: "overrides": {{"{name}": "{target}"}}  then npm install')
    if eco == "Maven":
        return f"set <version>{target}</version> for {name} (use <dependencyManagement> to force it for transitive use)"
    if eco == "Go":
        return f"go get {name}@v{target} && go mod tidy"
    if eco == "crates.io":
        return f"cargo update -p {name} --precise {target}"
    if eco == "RubyGems":
        return f"bundle update {name}   # confirm the result is >= {target}"
    if eco == "Packagist":
        return f"composer require {name}:{target}" if direct is not False else f"composer update {name}   # need >= {target}"
    if eco == "NuGet":
        return f"dotnet add package {name} --version {target}"
    if eco == "ConanCenter":
        return f"change the requirement to {name}/{target} in conanfile.txt, then conan install"
    return f"upgrade {name} to {target}"
