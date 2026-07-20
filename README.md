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
