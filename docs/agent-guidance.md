# zk-location Shared Agent Guidance

This document contains the shared project rules for Claude Code, Codex, and their subagents.

## Repository

* Repository root: `/home/lyy/projects/zk-location`
* Stable branch: `main`
* Stable baseline commit: `c17a5455f2a88589a53be2c21c663ed357e6cb9e`
* Remote: `git@github.com:liu1845544692-glitch/zk-location.git`

Always inspect the current Git state before working. The baseline commit may no longer be the latest commit.

## Git safety

Before working, run:

```bash
git rev-parse --show-toplevel
git status --short
git branch --show-current
git log -1 --oneline
```

Rules:

* Do not edit `main` directly.
* Do not use `git reset --hard`.
* Do not discard or overwrite uncommitted changes.
* Do not rewrite history.
* Do not force-push.
* Do not commit or push unless explicitly requested.
* Use a separate branch and worktree for each independent agent.
* If unexpected changes exist, stop and report them.

## Main project modules

The project currently includes:

* Android GNSS and Location Groth16 proof.
* Seven Regex proofs:

  * Source IP
  * Destination IP
  * Timestamp
  * Port
  * Trans
  * Unit
  * Protocol
* Password-policy Groth16 proof.
* Android Password Register.
* Server-side password proof verification.
* Android Password Login.
* Server-side public salt storage and retrieval.
* Login that does not depend on a local salt file.

## Password policy

Passwords must:

* have length 8 through 32;
* contain at least one lowercase letter;
* contain at least one uppercase letter;
* contain at least one digit;
* contain at least one allowed special character.

Allowed characters:

```text
A-Z
a-z
0-9
!@#$%^&*
```

The policy is enforced by five zk-regex DFA modules:

* lowercase
* uppercase
* digit
* special
* length

## Password commitment

The commitment definition is:

```text
passwordCommitment =
Poseidon(chunk0, chunk1, passwordLength, salt)
```

Do not change:

* password encoding;
* chunk construction;
* byte order;
* password length semantics;
* Poseidon parameters;
* salt interpretation;
* field-element representation.

Registration and login must use exactly the same Rust commitment implementation.

## Salt

Salt is a public, non-secret parameter.

Current behavior:

* Android generates a random nonzero salt.
* Salt participates in the password commitment.
* Registration sends salt to the server.
* The server stores salt with the user registration.
* Login fetches salt from the server.
* Login must still work when no local salt file exists.

Do not remove salt or replace it with a fixed value, timestamp, counter, or weak random source.

## Proof contracts

Password proof:

```text
publicSignals.length == 1
publicSignals[0] == passwordCommitment
```

Location proof:

```text
publicSignals.length == 37
publicSignals[0] == public commitment
```

Do not incorrectly apply the password public-input contract to Location.

Login intentionally does not generate a Groth16 proof.

## RustWitness input format

The shared witness normalization must produce values compatible with:

```text
HashMap<String, Vec<String>>
```

It must:

* convert numeric scalars to one-element decimal string arrays;
* convert string scalars to one-element string arrays;
* convert numeric arrays to decimal string arrays;
* preserve valid string arrays;
* explicitly reject unsupported objects, nested arrays, booleans, and null values.

Unsupported values must never be silently discarded.

## Protected artifacts

Do not modify, regenerate, replace, or delete without explicit permission:

* Circom circuits;
* DFA graph files;
* R1CS;
* WASM;
* zkey;
* vkey;
* ptau;
* committed native libraries;
* fixed test vectors.

The password verification key is:

```text
server/keys/password_policy_commitment_verification_key.json
```

## Sensitive information

Never log, persist, upload, or include in reports:

* plaintext passwords;
* confirm-password values;
* private witness values;
* padded password arrays;
* password chunks;
* DFA paths;
* private keys;
* Keystore key material;
* API tokens;
* GitHub tokens.

Public salt may be stored by the server, but routine logs should not print the full salt.

## Accepted prototype limitations

The following are known limitations, not automatically bugs:

* login has no nonce or challenge;
* login currently has no replay protection;
* login submits a static commitment;
* JWT and session tokens are not implemented;
* password reset and account recovery are not implemented;
* local development may use HTTP;
* production deployment requires HTTPS.

Do not implement these features unless explicitly requested.

## Bug-audit rules

Classify every finding as one of:

* Confirmed Bug
* Potential Risk
* Known Limitation
* Not a Bug

A Confirmed Bug requires concrete evidence, such as:

* a failing test;
* a reliable reproduction;
* a demonstrated incorrect state;
* a clear code path producing wrong behavior.

Do not modify production code before reproducing the problem.

For every confirmed bug:

* identify the root cause;
* make the smallest correct fix;
* add a regression test where feasible;
* run focused tests;
* run the full affected test suite.

Do not weaken validation or remove tests to obtain a passing result.

## Required validation

Rust:

```bash
cargo fmt --check
cargo check --all-targets --offline
cargo test --offline
```

Android:

```bash
./gradlew testDebugUnitTest
./gradlew lintDebug
./gradlew assembleDebug
```

Server:

* Inspect the existing scripts.
* Run the complete current server test suite.
* Do not use forced dependency upgrades.

Run a real-device test only when changes affect Android runtime behavior, native code, proving, Keystore, networking, or lifecycle behavior.

## Parallel-agent rules

Parallel agents may perform read-only audits in separate worktrees.

Recommended audit areas:

1. Rust, witness normalization, UniFFI, proof handling.
2. Android lifecycle, concurrency, Keystore, networking.
3. Server validation, persistence, concurrency.
4. Location and Regex artifact mapping.

During the audit phase:

* agents must not modify production code;
* agents must not share the same worktree;
* agents must provide file paths, functions, and reproduction evidence.

During the fix phase:

* only one agent should modify a given bug;
* another agent may independently review the diff;
* two agents must not edit the same files concurrently.

## Final checks

Before finishing, confirm:

* no plaintext password leakage;
* no private witness leakage;
* no protected proving artifact modification;
* no unintended Git operation;
* all relevant tests were executed;
* all reported bugs are supported by evidence.
