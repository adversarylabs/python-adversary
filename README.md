# Python adversary

Reviews Python for shell injection, unsafe YAML, and disabled TLS verification.

## Checks

- **Subprocess executes through a shell:** Pass an argument list with shell=False.
- **PyYAML loads objects unsafely:** Use yaml.safe_load or SafeLoader.
- **HTTP request disables certificate verification:** Keep TLS verification enabled.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```

## Automatic detection

`adversary auto` selects the python adversary when changes include `**/*.py`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.
