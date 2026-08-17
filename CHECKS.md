# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `python.default-empty-destructive-sync` | High | Synchronization code defaults a missing response collection to empty and uses it to drive destructive cleanup |
| `python.eval-exec-dynamic` | Critical | `eval()` / `exec()` on non-literal input |
| `python.flask-debug` | High | Flask/FastAPI/Starlette debug or reload enabled for production entrypoints |
| `python.mark-safe-user-input` | High | Django `mark_safe` / Jinja `\|safe` on user-influenced data |
| `python.os-system` | Critical | `os.system` / `os.popen` with dynamic command strings |
| `python.pickle-loads` | Critical | `pickle.loads` / `pickle.load` / `cPickle` on non-literal data |
| `python.requests-no-timeout` | Medium | `requests` (or `urllib.request`) network calls without a timeout |
| `python.shell-true` | Critical | `subprocess` invoked with `shell=True` and a non-constant command |
| `python.sql-format-fstring` | High | SQL built with f-strings / `%` / `.format` into execute |
| `python.sqlalchemy-offline-postgres-literal` | Medium | Offline SQLAlchemy PostgreSQL literal rendering strips generated quotes while retaining the default backslash mode |
| `python.tempfile-mktemp` | Medium | Use of deprecated `tempfile.mktemp` or predictable temp paths |
| `python.tls-disabled` | High | TLS verification disabled on HTTP clients |
| `python.unsafe-yaml` | Critical | PyYAML `yaml.load` without SafeLoader / `safe_load` |
