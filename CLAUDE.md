# Claude Code Project Instructions

Read and follow:

@docs/agent-guidance.md

Claude-specific rules:

* You may use parallel read-only subagents during Bug auditing.
* Suggested subagent scopes:

  1. Android lifecycle, concurrency, Keystore, and networking.
  2. Rust witness, UniFFI, commitment, and proof handling.
  3. Server validation, persistence, and concurrency.
  4. Location and Regex proving-artifact mapping.
* Subagents must not modify production files during the audit phase.
* Merge and deduplicate all subagent findings before proposing fixes.
* Do not commit or push unless explicitly requested.
