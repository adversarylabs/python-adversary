# Python adversary

Reviews Python for security, reliability, and correctness hazards, including expiring OAuth bearer reuse in long-running request workflows.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates Python source for command and code execution, deserialization, SQL construction, TLS, HTTP timeouts, temporary files, template safety, weak hashing, destructive synchronization defaults, and structurally proven OAuth client-credentials refresh gaps.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It owns framework- or language-specific review in this domain. Infrastructure, CI, dependency-manager, and unrelated application concerns remain with specialist adversaries.
