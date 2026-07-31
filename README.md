# python

**python** reviews Python source for **shell injection, unsafe deserialization (pickle/YAML), disabled TLS, SQL string building, and hung HTTP clients**.

It is a **language security reviewer**, not a style linter. When it reports, code likely enables RCE, MITM, or injection with high confidence.

## What it does

1. **Discovers** `*.py` files (skipping common vendor trees).
2. **Runs deterministic detectors** for dangerous APIs and patterns.
3. **Synthesizes a review** with file:line evidence.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)**.

Highlights:

| Area | Examples |
| --- | --- |
| Injection | shell=True, os.system, SQL f-strings |
| Deserialization | pickle.loads, yaml.load without SafeLoader, eval/exec |
| Transport | verify=False |
| Reliability | requests without timeout |

### Ownership boundaries

| Concern | Owned by |
| --- | --- |
| Poetry/pip lock supply chain | `poetry` package-manager adversaries |
| Generic secret scanning | [`security/secrets`](https://github.com/adversarylabs/secrets-adversary) |
| Dockerfile Python bases | [`container/dockerfile`](https://github.com/adversarylabs/dockerfile-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire.
- Prefer missing a weak signal over a false positive on normal production code.
