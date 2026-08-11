> **Shipped in 0.0.4:** , , , , , , , , 
>
> Rules documented below that are not in that list are deferred (not yet in `src/spec.ts`).

# Checks — what python detects

This file is the **public audit list** of detectors for the **python** adversary. High-confidence Python security defects with file:line evidence—not a general style linter (no PEP8, no import sorting).

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `*.py` (and `*.pyi` only if needed). Skip vendored trees (`**/site-packages/**`, `**/.venv/**`, `**/venv/**`) when path heuristics allow.

**Precision stance:** Dangerous APIs on clearly dynamic data fire. Safe loaders and argv-list subprocess stay quiet. Prefer missing weak signals over flagging every `subprocess` call.

Public grounding: [CVE-2017-18342](https://nvd.nist.gov/vuln/detail/CVE-2017-18342) (PyYAML `yaml.load`), pickle RCE literature ([Tony Baloney’s Python gotchas](https://tonybaloney.github.io/posts/10-common-security-gotchas-in-python.html)), and [Snyk command-injection guidance](https://snyk.io/blog/command-injection-python-prevention-examples/).

---

## Critical

### `python.shell-true`

| | |
| --- | --- |
| **What** | `subprocess` invoked with `shell=True` and a non-constant command |
| **Why** | Classic OS command injection when user-controlled strings reach the shell |
| **Looks for** | `subprocess.Popen|run|call|check_output|check_call(..., shell=True` where the command argument is an f-string, `+` concat, `.format`, or variable—not a string literal only |
| **Stays quiet when** | `shell=False` (default) with argv list; or `shell=True` with a **constant** literal string and no interpolation |
| **Public examples** | [Snyk: Command injection in Python](https://snyk.io/blog/command-injection-python-prevention-examples/); OWASP command injection |
| **Remediation** | Pass an argument list with `shell=False` |

### `python.os-system`

| | |
| --- | --- |
| **What** | `os.system` / `os.popen` with dynamic command strings |
| **Why** | Always goes through the shell; no argv form |
| **Looks for** | `os.system(` / `os.popen(` with f-string or concat |
| **Stays quiet when** | Constant literal only (still medium—prefer subprocess list form) |
| **Public examples** | Same class as shell=True; common in older scripts |
| **Remediation** | Replace with `subprocess.run([...], check=True)` |

### `python.pickle-loads`

| | |
| --- | --- |
| **What** | `pickle.loads` / `pickle.load` / `cPickle` on non-literal data |
| **Why** | Pickle is an execution format; untrusted pickle is RCE |
| **Looks for** | `pickle.loads(`, `pickle.load(`, `joblib.load(` on variables, network/file inputs; `torch.load(..., weights_only=False)` (torch ≥ 2.6 defaults to `weights_only=True`; older torch is unsafe by default) |
| **Stays quiet when** | Clearly test-only fixtures under `tests/` loading checked-in blobs **and** not from request paths—default: still fire on application code |
| **Public examples** | [Tony Baloney pickle examples](https://tonybaloney.github.io/posts/10-common-security-gotchas-in-python.html); ML model pickle warnings |
| **Remediation** | Use JSON/msgpack/protobuf; never unpickle untrusted data |

### `python.unsafe-yaml`

| | |
| --- | --- |
| **What** | PyYAML `yaml.load` without SafeLoader / `safe_load` |
| **Why** | Historical full-loader RCE on untrusted YAML ([CVE-2017-18342](https://nvd.nist.gov/vuln/detail/CVE-2017-18342)) |
| **Looks for** | Any `yaml.load(` whose Loader is absent or not SafeLoader/CSafeLoader. Treat `FullLoader` as low severity (blocks direct code execution but had bypasses — CVE-2020-14343, fixed in PyYAML 5.4) |
| **Stays quiet when** | `yaml.safe_load`, `yaml.load(..., Loader=yaml.SafeLoader)`, or `CSafeLoader` |
| **Public examples** | CVE-2017-18342; PyYAML 5.1+ migration notes |
| **Remediation** | Use `yaml.safe_load` or SafeLoader exclusively |

### `python.eval-exec-dynamic`

| | |
| --- | --- |
| **What** | `eval()` / `exec()` on non-literal input |
| **Why** | Direct code injection when any dynamic data reaches them |
| **Looks for** | `eval(` / `exec(` with a variable, f-string, concat, or call result as the argument |
| **Stays quiet when** | Constant string literals (still discouraged); `ast.literal_eval` |
| **Public examples** | Bandit B307; OWASP code injection guidance |
| **Remediation** | Use `ast.literal_eval` for data, or redesign to avoid dynamic code |

---

## High

### `python.tls-disabled`

| | |
| --- | --- |
| **What** | TLS verification disabled on HTTP clients |
| **Why** | MITM on credentials and tokens |
| **Looks for** | `verify=False` in `requests.*`, `httpx.*`, `urllib3` disable warnings + verify false; `ssl._create_unverified_context` |
| **Stays quiet when** | `verify=True` or omitted (default verify) |
| **Public examples** | Requests docs warn against verify=False; common in “fix fix” commits that never revert |
| **Remediation** | Keep verification on; fix CA trust properly |

### `python.sql-format-fstring`

| | |
| --- | --- |
| **What** | SQL built with f-strings / `%` / `.format` into execute |
| **Why** | SQL injection |
| **Looks for** | `cursor.execute` / `connection.execute` / raw Django `.raw` / SQLAlchemy `text()` with f-string or percent-format including variables |
| **Stays quiet when** | Parameterized execute (`%s` / `?` placeholders with separate params tuple); SQLAlchemy bound params |
| **Public examples** | OWASP SQLi; common Flask/Django anti-patterns |
| **Remediation** | Bound parameters only |

### `python.flask-debug`

| | |
| --- | --- |
| **What** | Flask/FastAPI/Starlette debug or reload enabled for production entrypoints |
| **Why** | Debug mode can expose interactive debuggers and secrets |
| **Looks for** | `app.run(debug=True)`, `FLASK_DEBUG=1` in committed env samples used by app code, `uvicorn.run(..., reload=True)` in `__main__` without env guard |
| **Stays quiet when** | Debug gated on environment explicitly false in prod paths |
| **Public examples** | Flask security notes on debug mode |
| **Remediation** | Never enable debug in production |

### `python.mark-safe-user-input`

| | |
| --- | --- |
| **What** | Django `mark_safe` / Jinja `|safe` on user-influenced data |
| **Why** | XSS |
| **Looks for** | `mark_safe(` with variables; Jinja `{{ ... | safe }}` patterns in templates when co-located |
| **Stays quiet when** | Applied to constant literals only |
| **Public examples** | Django XSS guidance |
| **Remediation** | Autoescape; avoid mark_safe on untrusted data |

---

## Medium

### `python.assert-used-for-security`

| | |
| --- | --- |
| **What** | Authorization / authn checks implemented only with `assert` |
| **Why** | Assertions are stripped with `-O` |
| **Looks for** | `assert request.user.is_authenticated` / `assert role ==` style in request handlers |
| **Stays quiet when** | Real `if` + raise/return used for authz |
| **Public examples** | Python assert optimization footgun writeups |
| **Remediation** | Use explicit checks that always run |

### `python.tempfile-mktemp`

| | |
| --- | --- |
| **What** | Use of deprecated `tempfile.mktemp` or predictable temp paths |
| **Why** | Race conditions / temp file hijack |
| **Looks for** | `mktemp(` |
| **Stays quiet when** | `NamedTemporaryFile` / `mkstemp` |
| **Public examples** | Python tempfile docs deprecation |
| **Remediation** | Use secure tempfile APIs |

### `python.hashlib-md5-sha1-security`

| | |
| --- | --- |
| **What** | MD5/SHA1 used in clearly security-sensitive contexts (password, token, signature) |
| **Why** | Broken for collision-sensitive uses |
| **Looks for** | `hashlib.md5` / `sha1` near password/token/sign variable names |
| **Stays quiet when** | Used for non-security checksums/ETags without secret context (noisy otherwise—require nearby keyword); `usedforsecurity=False` (Python 3.9+) explicitly marks non-security use |
| **Public examples** | Cryptographic guidance deprecating MD5/SHA1 for security |
| **Remediation** | Use SHA-256+ or password KDFs (bcrypt/argon2/scrypt) |

### `python.requests-no-timeout`

| | |
| --- | --- |
| **What** | `requests` (or `urllib.request`) network calls without a timeout |
| **Why** | `requests` has **no default timeout** — a hung endpoint hangs the worker forever; a recurring production-outage class |
| **Looks for** | `requests.get/post/put/patch/delete/head/request(` and `Session()` calls without `timeout=`; `urllib.request.urlopen(` without timeout |
| **Stays quiet when** | `timeout=` present; a shared session/adapter demonstrably sets a default; `httpx` (ships a 5s default) |
| **Public examples** | requests documentation explicitly advises always setting a timeout; hung-worker postmortems |
| **Remediation** | Pass `timeout=` on every call or set it at session/transport level |

### `python.sqlalchemy-offline-postgres-literal`

| | |
| --- | --- |
| **What** | Offline SQLAlchemy PostgreSQL literal rendering strips generated quotes while retaining the default backslash mode |
| **Why** | PostgreSQL backslash behavior is normally derived from a live connection; an offline dialect can silently change backslash-containing values |
| **Looks for** | Production Python that obtains an offline dialect, builds `statement_compiler(..., None)`, calls `render_literal_value`, and slices `[1:-1]` without explicitly disabling PostgreSQL backslash escaping or restricting the renderer to MySQL/MariaDB |
| **Stays quiet when** | Queries use bound parameters; the renderer is statically limited to MySQL/MariaDB, where backslash doubling is intentional; PostgreSQL mode is explicitly configured; generated quotes are retained; code is test-only |
| **Public examples** | [Apache Superset review](https://github.com/apache/superset/pull/33924#discussion_r3693512209) and [resolution](https://github.com/apache/superset/pull/33924#discussion_r3717371929) |
| **Remediation** | Prefer bound parameters; otherwise configure the target PostgreSQL semantics explicitly and test quotes and backslashes |

---

## Out of scope

| Concern | Owner |
| --- | --- |
| Poetry/pip lock supply chain | `poetry` / package-manager adversaries |
| Generic committed secrets | `security/secrets` |
| Dockerfile Python base | `container/dockerfile` |
| FastAPI-specific API design beyond security | `fastapi` adversary when specialized |
