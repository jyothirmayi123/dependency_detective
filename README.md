# Dependency Detective

Multi-language software supply-chain risk analyzer. It scans dependency files for **Python, JavaScript/Node, Java, C/C++ (Conan), Go, Rust, Ruby, PHP and .NET**, matches them against OSV advisory data, traces each vulnerability through the dependency tree, ranks the work by risk and produces a fix plan, SBOM and CI-ready reports.

## 1. Problem Statement
Projects depend on external packages (often hundreds, mostly indirect) that may have known vulnerabilities. Developers need to know which versions are affected, how the package got into the project, what to fix first, and what fixes exist, in every language they use.

## 2. Objectives
- Parse manifests **and lockfiles** for 9 ecosystems, never executing anything
- Match exact versions against advisory data (OSV online, or cached/offline)
- Resolve **transitive dependencies** and show the path that introduced each risk
- Prioritise with a transparent risk score; suggest upgrades only when advisory data supports them
- Export reports for people (Markdown/CSV), tools (JSON, SARIF, CycloneDX SBOM) and pipelines (CLI exit codes)

## 3. Features
| Area | What it does |
|---|---|
| Languages | requirements.txt, poetry.lock, Pipfile.lock · package.json, package-lock.json · pom.xml, build.gradle(.kts) · conanfile.txt, conan.lock · go.mod · Cargo.toml, Cargo.lock · Gemfile.lock · composer.json, composer.lock · *.csproj, packages.config |
| Detection | Format auto-detected from file name or content; several files per scan (monorepos) |
| Transitive analysis | NetworkX dependency graph, direct vs transitive, "introduced via" chains, blast radius, interactive graph view |
| Risk scoring | CVSS v3.x base score computed from the advisory's vector + optional **EPSS** and **CISA KEV** exploit signals + exposure -> 0-100 priority |
| Fix plan | Highest risk first; minimal safe version per package; patch/minor/major label; copy-paste command per ecosystem; direct artifact download links where the registry provides a stable URL; transitive hints (parent upgrade / override) |
| Supply-chain signals | Typosquat heuristic (names one edit from popular npm/PyPI packages) |
| Honest results | Six states: confirmed / unresolved / no matching record / lookup unavailable / malformed / skipped. "No match" never means "safe" |
| Online mode | OSV batch API with pagination, parallel advisory download, withdrawn records ignored, SQLite cache |
| Exports | Markdown, CSV, JSON, **CycloneDX 1.5 SBOM**, **SARIF 2.1.0**, fixed requirements.txt |
| CLI + CI | `python -m backend.cli scan ...` with `--fail-on` exit codes; example GitHub Actions workflow included |
| History | Scan history and before/after comparison |

## 4. Technology Stack
Python 3.12 (3.11+ required for `tomllib`), Streamlit, NetworkX, `packaging`, requests, pandas, Plotly, SQLite, pytest. No LLM and no API key needed.

## 5. Architecture
```
files / paste -> validators -> format detection -> ecosystem parser -> entries
   -> dependency graph (direct/transitive, paths)
   -> advisory lookup (OSV API  |  cached + bundled dataset, indexed)
   -> version matcher (per-ecosystem comparator) -> CVSS + EPSS/KEV -> risk score
   -> remediation (minimal safe version) -> fix plan + typosquat signals
   -> report dict -> UI / CLI / exports / history
```

## 6. Project Structure
```
server.py                 FastAPI server + JSON API for the custom frontend
web/index.html            custom single-page frontend (drag & drop, dashboard, graph, fix plan, exports, history)
app.py                    alternative Streamlit UI (tabs: Findings, Fix plan, Dependency graph, All packages, Charts, Export)
pages/1_History.py        scan history + comparison
components/ui.py          theme + UI helpers
backend/ecosystems.py     ecosystem registry, name normalisation, package URLs (purl)
backend/versioning.py     version comparison across ecosystems
backend/parsers/          one module per language + format detection (registry in __init__.py)
backend/core/             matcher, risk (CVSS/priority), graph, typosquat, remediation, scanner, compare
backend/services/         osv_service (pagination, parallel), enrichment (EPSS, KEV)
backend/utils/            validators, db, report (all export formats)
backend/cli.py            command line / CI entry point
data/sample/              multi-language demo files + advisories_sample.json
tests/                    pytest suite
.github/workflows/        example CI workflow
```

## 7. Prerequisites
Python 3.11 or 3.12, Git. Internet only for online mode and exploit signals.

## 8. Installation
```
git clone <repo-url> && cd dependency-detective
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

## 9. Run
```
uvicorn server:app --reload                            # custom web frontend -> http://127.0.0.1:8000
streamlit run app.py                                   # alternative Streamlit UI
python -m backend.cli scan . --mode online --fail-on high   # command line / CI
python -m backend.cli scan requirements.txt package-lock.json --format cyclonedx -o sbom.json
python -m backend.cli formats                          # list supported files
```
CLI exit codes: `0` ok, `1` finding at/above `--fail-on`, `2` input error or lookup unavailable.

## 10. How to Use
Click **Load multi-language demo**, choose a source, click **Scan dependencies**. The demo has one file per language. Look for: `log4j-core` (Java), a **transitive** `minimist` reached through `mkdirp` (JavaScript, open *Dependency graph*), `zlib`/`openssl` (C/C++), `regex` (Rust), `golang.org/x/net` as an indirect Go dependency, the typosquat-looking `expresss`, and unresolved lines (`boost` range, BOM-managed `guava`, `Dapper` floating version). Then open **Fix plan**.

**Tip:** upload lockfiles when you have them. Manifests such as `requirements.txt` or `package.json` only state ranges or direct dependencies; lockfiles give exact versions and the whole tree.

## 11. Configuration
Optional, in `.env` or Streamlit secrets: `OSV_API_URL` (default `https://api.osv.dev/v1`), `EPSS_API_URL`, `KEV_URL`.

## 12. How the risk score works
`priority = 60 x (CVSS/10) + 25 x exploitation + exposure` (max 100)
- *CVSS*: computed from the advisory's CVSS v3 vector; if there is only a severity label, a mid-band value for that label is assumed.
- *Exploitation*: 25 if the CVE is in CISA KEV, else `25 x EPSS`; 0 without enrichment.
- *Exposure*: 10 for a direct dependency, 5 transitive (7 unknown), +1 per dependent package up to 5.
Bands: >=75 critical, >=55 high, >=35 medium. It is a **heuristic for ordering work**, not a verdict.

## 13. Testing
`python -m pytest -q` (~120 tests: every parser, version ordering, CVSS formula, matching per ecosystem, graph/paths, typosquat, SARIF/CycloneDX shape, OSV pagination, enrichment failure handling, CLI exit codes). Network calls are mocked.

## 14. Screenshots / Demo
Add screenshots to `assets/` and the live Streamlit Cloud URL here.

## 15. Known Limitations
- **Bundled advisories are a small hand-assembled demo subset.** Verify at osv.dev; online mode is authoritative.
- Offline version comparison for non-Python ecosystems is a tolerant approximation (semver, Maven qualifiers, letter suffixes). Online mode uses OSV's own matching.
- **C/C++ has no universal package manager.** Only Conan packages (ConanCenter) are covered; vendored, system or CMake-fetched libraries are invisible to manifest parsing.
- Version ranges, BOM/parent-managed versions and floating versions cannot be resolved without a lockfile and are listed as *unresolved*.
- Go `replace` directives, Cargo/npm git dependencies and npm workspaces are not followed.
- Direct/transitive is read from the file where possible (package-lock, Cargo.lock, Gemfile.lock, go.mod) and inferred for poetry.lock/composer.lock; flat files (requirements.txt, pom.xml, Pipfile.lock) have no edges.
- No reachability analysis: a vulnerable package may be present but its vulnerable code never called.
- Typosquat detection is a name-similarity heuristic with a small bundled list of popular npm/PyPI names; it can false-positive.
- SQLite history is temporary on Streamlit Cloud. Upgrades are not guaranteed compatible.

## 16. Privacy and Responsible Use
Files are processed in memory; only the report is stored locally. XML with DOCTYPE/ENTITY is rejected, uploads are size-limited, nothing from an uploaded file is executed. "No matching record" never means "safe". Do not upload private data.

## 17. Future Enhancements
Commit/hash-based C/C++ matching (OSV supports it), vcpkg/CMake FetchContent parsing, license compliance, "latest version" and deprecation checks from registries, call-graph reachability, auto-opened fix pull requests, zip/repo URL upload, local-LLM explanations from retrieved records.

## 18. Credits and License
Advisory data: OSV.dev and GitHub Advisory Database. Exploit signals: FIRST EPSS and CISA KEV. Add a license of your choice.
