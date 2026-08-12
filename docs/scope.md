# lang/python — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `python`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Python

## Mission

Review Python for shell injection, unsafe deserialization, disabled TLS, and SQL string building.

## In scope (fair miss if humans raised it and we did not)

- shell=True / injection
- pickle/yaml unsafe load
- verify=False TLS
- SQL string building
- Race-prone Python standard-library APIs with secure direct replacements

## Out of scope (not a miss for this adversary)

- Go/TS
- Pure docs

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
