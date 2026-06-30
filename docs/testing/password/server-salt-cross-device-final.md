# Server salt and cross-device login implementation

Date: 2026-06-29

## Result

- Registration request now includes the exact decimal salt used to construct the Rust circuit input.
- The password registration JSON store schema is version 2 and persists salt beside the commitment.
- `GET /password/login-parameters?userId=...` returns only salt and circuit version.
- Android login fetches server salt before computing the commitment.
- Missing or mismatched local encrypted salt does not block login; server salt wins.
- Legacy saltless records remain unchanged and return `ACCOUNT_REQUIRES_REREGISTRATION`.
- Login still generates no proof and sends no plaintext password.

## Automated verification

- Rust: 22 h3-converter tests and 15 zk-location tests passed.
- Server: 65 tests passed, including real Groth16 registration fixture, persisted salt, restart, migration, invalid salt, and server-salt login flow.
- Android JVM: 50 tests passed.
- Android `assembleDebug`: passed.

## Device verification

Completed on 2026-06-30 with a HUAWEI EBG-AN00 running Android 12/API 31. Registration, same-device login, deletion of the single test user's local encrypted salt file, cross-device login simulation, and login after server restart all passed. No OOM, ANR, app crash, native crash, or Rust panic was observed. See `device-server-salt-final-20260630.md` and the associated raw records in this directory.

## Existing data migration audit

`server/data/password-registrations.json` remains untouched at schema version 1. It currently contains two saltless records (`123456` and `lyynb`). The version-2 store loads them with an in-memory `saltMissing` marker; login-parameter retrieval returns `ACCOUNT_REQUIRES_REREGISTRATION`. Their commitments are not overwritten.

## APK

- Path: `zk-location/android/app/build/outputs/apk/debug/app-debug.apk`
- Size: 211359758 bytes
- SHA-256: `c6bd2fa4965e4e47c79ec11808fda2c061972dc4bdd655ee04e2683dfb62ec98`

## Security boundary

Salt is public and is not logged by the server. The current login protocol has no challenge or replay protection. LAN HTTP remains development-only; production requires HTTPS and a challenge-bound authentication protocol.
