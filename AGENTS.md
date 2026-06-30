# Codex Project Instructions

Before doing any work, read and follow:

```text
docs/agent-guidance.md
```

Codex-specific rules:

* Parallel read-only subagents may audit independent modules.
* Suggested subagent scopes:

  1. Server input validation, JSON persistence, and concurrency.
  2. Rust witness normalization and field-element boundaries.
  3. Android networking, state handling, and repeated requests.
  4. Location, Regex, and Password proving-artifact mapping.
* Subagents must not modify production files during the audit phase.
* Merge and deduplicate findings before proposing fixes.
* Do not commit or push unless explicitly requested.
