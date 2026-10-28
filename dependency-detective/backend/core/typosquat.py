"""Heuristic supply-chain signal: a package name one edit away from a very popular package.
This is a hint to double-check a name, never proof of a malicious package."""
from backend.ecosystems import normalize_name

POPULAR = {
    "PyPI": """requests numpy pandas urllib3 setuptools boto3 botocore certifi idna charset-normalizer typing-extensions
        python-dateutil six s3transfer pyyaml packaging cryptography wheel attrs jmespath pytz cffi pycparser click
        jinja2 markupsafe flask werkzeug itsdangerous django sqlalchemy scipy matplotlib pillow tensorflow torch
        scikit-learn pytest pydantic fastapi uvicorn aiohttp beautifulsoup4 lxml protobuf grpcio colorama tqdm
        psycopg2 redis celery gunicorn selenium openpyxl docutils pygments rich httpx black mypy coverage tomli
        networkx streamlit plotly seaborn nltk transformers keras opencv-python paramiko pymysql dnspython markdown
        jsonschema sympy regex simplejson ujson tornado pyparsing wrapt oauthlib""".split(),
    "npm": """react lodash express axios moment chalk commander debug request async underscore jquery vue angular webpack
        typescript eslint prettier jest mocha next redux rxjs uuid minimist mkdirp glob semver yargs inquirer dotenv
        body-parser cors mongoose bluebird colors fs-extra tslib classnames prop-types react-dom node-fetch cheerio
        passport jsonwebtoken bcrypt nodemon rimraf cross-env tailwindcss core-js socket.io puppeteer babel-core
        webpack-cli ts-node tsup vite rollup gulp grunt handlebars ejs pug morgan helmet multer nodemailer""".split(),
}
_SETS = {eco: set(names) for eco, names in POPULAR.items()}


def _osa(a: str, b: str) -> int:
    """Optimal-string-alignment edit distance (insert/delete/substitute/transpose)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            c = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def check(eco: str, name: str) -> dict | None:
    pop = _SETS.get(eco)
    n = normalize_name(eco, name or "")
    if not pop or len(n) < 6 or n in pop or n.startswith("@"):
        return None
    for p in POPULAR[eco]:
        if abs(len(p) - len(n)) <= 1 and len(p) >= 6 and _osa(n, p) == 1:
            return {"similar_to": p, "detail": f"'{name}' is one edit away from the popular package '{p}'. "
                                               f"Verify it is the package you intended."}
    return None
