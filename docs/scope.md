# lang/python — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `python`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Python, including Requests-based OAuth client lifecycles

## Mission

Review Python for security, reliability, and correctness hazards, including shell injection, unsafe deserialization, disabled TLS, SQL string building, and expiring OAuth bearer lifecycles.

## In scope (fair miss if humans raised it and we did not)

- shell=True / injection
- pickle/yaml unsafe load
- verify=False TLS
- SQL string building
- Race-prone Python standard-library APIs with secure direct replacements
- Client-credentials access tokens attached to shared Requests sessions and reused across proven repeated or multi-stage request paths without bounded refresh

## Out of scope (not a miss for this adversary)

- Go/TS
- Pure docs
- Static API keys, single bounded authenticated requests, and dynamically dispatched or cross-module token flows that cannot be structurally proven

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
